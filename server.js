const express = require("express");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const serverless = require("serverless-http");
require("dotenv").config();

const supabase = require("./database/database");

const app = express();
const PORT = process.env.PORT || 8080;

app.set("trust proxy", 1);

// Middleware for parsing JSON and form bodies in serverless
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets from public directory
app.use(express.static(path.join(__dirname, "public")));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "default_local_dev_secret_key_12345",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 8 // 8 hours
        }
    })
);

// --- MIDDLEWARE HELPERS ---

function requireAdmin(req, res, next) {
    if (req.session?.user?.role === "admin") return next();
    return res.status(403).json({ success: false, message: "Admin access required." });
}

function requireField(req, res, next) {
    if (req.session?.user?.role === "field_personnel") return next();
    return res.status(403).json({ success: false, message: "Field personnel access required." });
}

// --- STATIC PAGE ROUTES ---

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// --- AUTHENTICATION ENDPOINTS ---

app.post("/api/login", async (req, res) => {
    // Robust payload extraction across Netlify serverless events
    let payload = req.body || {};
    
    // If req.body came as a raw string, parse it
    if (typeof payload === "string") {
        try {
            payload = JSON.parse(payload);
        } catch (e) {
            payload = {};
        }
    }

    const username = payload.username || req.query?.username;
    const password = payload.password || req.query?.password;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Username and password required." });
    }

    const cleanUsername = String(username).trim().toLowerCase();

    try {
        // 1. Check Admins
        const { data: admin, error: adminErr } = await supabase
            .from("admins")
            .select("*")
            .eq("username", cleanUsername)
            .maybeSingle();

        if (adminErr) console.error("Admin Auth Error:", adminErr);

        if (admin) {
            const passwordMatch = await bcrypt.compare(password, admin.password);
            if (passwordMatch) {
                req.session.user = { id: admin.id, name: admin.full_name, username: admin.username, role: "admin" };
                return res.json({ success: true, message: "Admin login successful.", role: "admin", redirect: "/admin-dashboard.html" });
            }
        }

        // 2. Check Field Personnel
        const { data: personnel, error: fieldErr } = await supabase
            .from("field_personnel")
            .select("*")
            .eq("username", cleanUsername)
            .eq("active", 1)
            .maybeSingle();

        if (fieldErr) console.error("Field Personnel Auth Error:", fieldErr);

        if (personnel) {
            const passwordMatch = await bcrypt.compare(password, personnel.password);
            if (passwordMatch) {
                req.session.user = { id: personnel.id, name: personnel.full_name, username: personnel.username, role: "field_personnel" };
                return res.json({ success: true, message: "Login successful.", role: "field_personnel", redirect: "/field-dashboard.html" });
            }
        }

        return res.status(401).json({ success: false, message: "Invalid username or password." });
    } catch (err) {
        console.error("Login Exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/me", (req, res) => {
    if (!req.session?.user) return res.json({ loggedIn: false });
    return res.json({ loggedIn: true, user: req.session.user });
});

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => res.json({ success: true, message: "Logged out." }));
});

// --- FIELD PERSONNEL ENDPOINTS ---

app.post("/api/field/daily-record", requireField, async (req, res) => {
    try {
        const fieldPersonnelId = req.session.user.id;
        const { screening_date, town_name, food_handlers_screened } = req.body;
        const screened = Number(food_handlers_screened);

        if (!screening_date || !town_name || isNaN(screened) || screened < 0) {
            return res.status(400).json({ success: false, message: "Please provide valid screening details." });
        }

        const cleanedTown = town_name.trim();

        // Check for duplicate submission on same date by same officer
        const { data: existing } = await supabase
            .from("daily_records")
            .select("id")
            .eq("field_personnel_id", fieldPersonnelId)
            .eq("screening_date", screening_date)
            .maybeSingle();

        if (existing) {
            return res.status(400).json({ success: false, message: "A record for this date has already been submitted." });
        }

        // Resolve or create Town
        let townId;
        const { data: town } = await supabase
            .from("towns")
            .select("id")
            .ilike("town_name", cleanedTown)
            .maybeSingle();

        if (town) {
            townId = town.id;
        } else {
            const { data: newTown, error: townErr } = await supabase
                .from("towns")
                .insert({ town_name: cleanedTown })
                .select("id")
                .single();

            if (townErr) {
                console.error("Town insert error:", townErr);
                return res.status(500).json({ success: false, message: "Failed to save town details." });
            }
            townId = newTown.id;
        }

        // Insert Daily Screening Record
        const { data: record, error: recErr } = await supabase
            .from("daily_records")
            .insert({
                field_personnel_id: fieldPersonnelId,
                town_id: townId,
                screening_date,
                food_handlers_screened: screened,
                daily_rate: 100,
                amount_earned: 100
            })
            .select()
            .single();

        if (recErr) {
            console.error("Daily record insert error:", recErr);
            return res.status(500).json({ success: false, message: recErr.message || "Failed to save daily record." });
        }

        return res.json({ success: true, message: "Screening activity recorded successfully! (GH₵100 earned)", record });
    } catch (err) {
        console.error("Daily record exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/field/my-records", requireField, async (req, res) => {
    try {
        const { data: records, error } = await supabase
            .from("daily_records")
            .select("id, screening_date, food_handlers_screened, daily_rate, amount_earned, towns(town_name)")
            .eq("field_personnel_id", req.session.user.id)
            .order("screening_date", { ascending: false });

        if (error) {
            console.error("Fetch my-records error:", error);
            return res.status(500).json({ success: false, message: "Error fetching submissions." });
        }

        const formatted = (records || []).map(r => ({
            id: r.id,
            screening_date: r.screening_date,
            town_name: r.towns?.town_name || "N/A",
            food_handlers_screened: r.food_handlers_screened,
            daily_rate: r.daily_rate,
            amount_earned: r.amount_earned
        }));

        return res.json({ success: true, records: formatted });
    } catch (err) {
        console.error("My records exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/field/summary", requireField, async (req, res) => {
    try {
        const { data: recs, error } = await supabase
            .from("daily_records")
            .select("food_handlers_screened, amount_earned")
            .eq("field_personnel_id", req.session.user.id);

        if (error) console.error("Field summary error:", error);

        const daysWorked = recs?.length || 0;
        const totalScreened = recs?.reduce((sum, r) => sum + (r.food_handlers_screened || 0), 0) || 0;
        const totalEarned = recs?.reduce((sum, r) => sum + (Number(r.amount_earned) || 0), 0) || 0;

        return res.json({ success: true, summary: { days_worked: daysWorked, total_screened: totalScreened, total_earned: totalEarned } });
    } catch (err) {
        console.error("Field summary exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

// --- ADMIN ENDPOINTS ---

app.get("/api/admin/summary", requireAdmin, async (req, res) => {
    try {
        const { count: personnel } = await supabase.from("field_personnel").select("*", { count: "exact", head: true }).eq("active", 1);
        const { count: days } = await supabase.from("daily_records").select("*", { count: "exact", head: true });

        const { data: recs } = await supabase.from("daily_records").select("food_handlers_screened, amount_earned");
        const screened = recs?.reduce((sum, r) => sum + (r.food_handlers_screened || 0), 0) || 0;
        const totalEarned = recs?.reduce((sum, r) => sum + (Number(r.amount_earned) || 0), 0) || 0;

        const { data: pmts } = await supabase.from("payments").select("amount");
        const totalPaid = pmts?.reduce((sum, p) => sum + (Number(p.amount) || 0), 0) || 0;

        return res.json({
            success: true,
            summary: {
                personnel: personnel || 0,
                days: days || 0,
                screened,
                earned: totalEarned,
                paid: totalPaid,
                balance: totalEarned - totalPaid
            }
        });
    } catch (err) {
        console.error("Admin summary exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/admin/all-records", requireAdmin, async (req, res) => {
    try {
        const { data: records, error } = await supabase
            .from("daily_records")
            .select("id, screening_date, food_handlers_screened, amount_earned, field_personnel(full_name), towns(town_name)")
            .order("screening_date", { ascending: false });

        if (error) {
            console.error("Fetch all records error:", error);
            return res.status(500).json({ success: false, message: "Failed to fetch master log." });
        }

        const formatted = (records || []).map(r => ({
            id: r.id,
            screening_date: r.screening_date,
            officer_name: r.field_personnel?.full_name || "Unknown Officer",
            town_name: r.towns?.town_name || "N/A",
            food_handlers_screened: r.food_handlers_screened,
            amount_earned: r.amount_earned
        }));

        return res.json({ success: true, records: formatted });
    } catch (err) {
        console.error("All records exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/admin/personnel-list", requireAdmin, async (req, res) => {
    try {
        const { data: personnel, error } = await supabase
            .from("field_personnel")
            .select("id, full_name, username, phone")
            .eq("active", 1)
            .order("full_name", { ascending: true });

        if (error) {
            console.error("Fetch personnel list error:", error);
            return res.status(500).json({ success: false, message: "Failed to fetch officers." });
        }

        return res.json({ success: true, personnel: personnel || [] });
    } catch (err) {
        console.error("Personnel list exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.post("/api/admin/create-field-personnel", requireAdmin, async (req, res) => {
    try {
        const { full_name, username, password, phone } = req.body;
        if (!full_name || !username || !password) {
            return res.status(400).json({ success: false, message: "Full name, username, and password required." });
        }

        const cleanUsername = username.trim().toLowerCase();
        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: person, error } = await supabase
            .from("field_personnel")
            .insert({
                full_name: full_name.trim(),
                username: cleanUsername,
                password: hashedPassword,
                phone: (phone || "").trim(),
                active: 1
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase Create Field Officer Error:", error);
            return res.status(400).json({ 
                success: false, 
                message: error.message || "Username already exists or invalid data." 
            });
        }

        return res.json({ success: true, message: "Account created successfully.", personnel: person });
    } catch (err) {
        console.error("Create field personnel exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get("/api/admin/claim-sheet/:id", requireAdmin, async (req, res) => {
    try {
        const personnelId = req.params.id;

        const { data: person } = await supabase.from("field_personnel").select("id, full_name").eq("id", personnelId).single();
        if (!person) return res.status(404).json({ success: false, message: "Personnel not found." });

        const { data: records } = await supabase
            .from("daily_records")
            .select("screening_date, food_handlers_screened, daily_rate, amount_earned, towns(town_name)")
            .eq("field_personnel_id", personnelId)
            .order("screening_date", { ascending: true });

        const { data: pmts } = await supabase.from("payments").select("amount").eq("field_personnel_id", personnelId);
        const totalPaid = pmts?.reduce((sum, p) => sum + (Number(p.amount) || 0), 0) || 0;

        const formattedRecords = (records || []).map(r => ({
            screening_date: r.screening_date,
            town_name: r.towns?.town_name || "N/A",
            food_handlers_screened: r.food_handlers_screened,
            daily_rate: r.daily_rate,
            amount_earned: r.amount_earned
        }));

        const totalEarned = formattedRecords.reduce((sum, r) => sum + Number(r.amount_earned || 0), 0);

        return res.json({
            success: true,
            claim: {
                full_name: person.full_name,
                records: formattedRecords,
                total_days: formattedRecords.length,
                total_earned: totalEarned,
                total_paid: totalPaid,
                balance: totalEarned - totalPaid
            }
        });
    } catch (err) {
        console.error("Claim sheet exception:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

// Start local HTTP listener when running node locally
if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => {
        console.log("==================================================");
        console.log(`Food Vendor Portal Running Locally`);
        console.log(`Access Portal At: http://localhost:${PORT}`);
        console.log("==================================================");
    });
}

// Netlify Serverless Export Wrapper
module.exports = app;
module.exports.handler = serverless(app);