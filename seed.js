const bcrypt = require("bcrypt");
const supabase = require("./database/database");

async function seedAdmin() {
    console.log("Seeding default admin account into Supabase...");

    const plainPassword = "admin123";
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    // Delete existing admin1 to avoid conflicts
    await supabase.from("admins").delete().eq("username", "admin1");

    // Insert admin1 with fresh local hash
    const { data, error } = await supabase
        .from("admins")
        .insert({
            full_name: "Administrator 1",
            username: "admin1",
            password: hashedPassword
        })
        .select();

    if (error) {
        console.error("Error seeding admin:", error.message);
    } else {
        console.log("Successfully created admin account!");
        console.log("Username: admin1");
        console.log("Password: admin123");
    }
    process.exit(0);
}

seedAdmin();