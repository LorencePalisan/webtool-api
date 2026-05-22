const fs = require('fs/promises');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

// --- Database Connection Configuration ---
// This uses the same environment variables as your server.js
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'nexus',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'nexus_portal',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

/**
 * Creates the necessary tables if they don't exist.
 * This is the same logic as in server.js to ensure consistency.
 * @param {mysql.PoolConnection} connection The database connection.
 */
async function createTables(connection) {
  console.log('Ensuring all required tables exist...');
  await connection.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id VARCHAR(36) PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      fullName VARCHAR(255) NOT NULL,
      role ENUM('user', 'admin') DEFAULT 'user',
      status ENUM('active', 'disabled') DEFAULT 'active',
      leaveCredits DECIMAL(5, 1) DEFAULT 20.0,
      must_change_password BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add must_change_password column to users table if it doesn't exist
  const [passwordColumns] = await connection.execute(`
    SHOW COLUMNS FROM users LIKE 'must_change_password'
  `);

  // Check and alter the leaveCredits column if it's still an INT
  const [leaveCreditColumns] = await connection.execute(`
    SHOW COLUMNS FROM users LIKE 'leaveCredits'
  `);

  if (leaveCreditColumns.length > 0 && leaveCreditColumns[0].Type.startsWith('int')) {
    console.log("Altering 'leaveCredits' column to DECIMAL(5, 1)...");
    await connection.execute(`ALTER TABLE users MODIFY COLUMN leaveCredits DECIMAL(5, 1) DEFAULT 20.0`);
  }

  if (passwordColumns.length === 0) {
    console.log("Adding 'must_change_password' column to 'users' table...");
    await connection.execute(`
      ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT FALSE
    `);
  }

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS pending_users (
      id VARCHAR(36) PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      fullName VARCHAR(255) NOT NULL,
      role ENUM('user', 'admin') DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      userEmail VARCHAR(255) NOT NULL,
      userName VARCHAR(255) NOT NULL,
      type VARCHAR(50) NOT NULL,
      timestamp VARCHAR(255) NOT NULL,
      image TEXT,
      location TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add todo and progress columns to logs table if they don't exist
  const [logColumns] = await connection.execute(`SHOW COLUMNS FROM logs`);
  const logColumnNames = logColumns.map(c => c.Field);

  if (!logColumnNames.includes('todo')) {
    console.log("Adding 'todo' column to 'logs' table...");
    await connection.execute(`
      ALTER TABLE logs ADD COLUMN todo TEXT DEFAULT NULL AFTER location
    `);
  }

  if (!logColumnNames.includes('progress')) {
    console.log("Adding 'progress' column to 'logs' table...");
    await connection.execute(`ALTER TABLE logs ADD COLUMN progress TEXT DEFAULT NULL AFTER todo`);
  }

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS holiday_requests (
      id VARCHAR(36) PRIMARY KEY,
      userEmail VARCHAR(255) NOT NULL,
      userName VARCHAR(255) NOT NULL,
      holidayName VARCHAR(255) NOT NULL,
      holidayDate DATE NOT NULL,
      details TEXT,
      status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
      timestamp VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS leave_applications (
      id VARCHAR(36) PRIMARY KEY,
      userEmail VARCHAR(255) NOT NULL,
      userName VARCHAR(255) NOT NULL,
      leaveType VARCHAR(255) NOT NULL,
      startDate DATE NOT NULL,
      endDate DATE NOT NULL,
      dayType ENUM('whole', 'half') DEFAULT 'whole',
      halfDayShift ENUM('morning', 'afternoon'),
      payType ENUM('withPay', 'withoutPay') DEFAULT 'withPay',
      details TEXT,
      status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
      timestamp VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Add dayType and payType to leave_applications if they don't exist
  const [leaveAppColumns] = await connection.execute(`SHOW COLUMNS FROM leave_applications`);
  const leaveAppColumnNames = leaveAppColumns.map(c => c.Field);

  if (!leaveAppColumnNames.includes('dayType')) {
    console.log("Adding 'dayType' column to 'leave_applications' table...");
    await connection.execute(`
      ALTER TABLE leave_applications ADD COLUMN dayType ENUM('whole', 'half') DEFAULT 'whole' AFTER endDate
    `);
  }

  if (!leaveAppColumnNames.includes('payType')) {
    console.log("Adding 'payType' column to 'leave_applications' table...");
    await connection.execute(`
      ALTER TABLE leave_applications ADD COLUMN payType ENUM('withPay', 'withoutPay') DEFAULT 'withPay' AFTER dayType
    `);
  }

  if (!leaveAppColumnNames.includes('halfDayShift')) {
    console.log("Adding 'halfDayShift' column to 'leave_applications' table...");
    await connection.execute(`
      ALTER TABLE leave_applications ADD COLUMN halfDayShift ENUM('morning', 'afternoon') DEFAULT NULL AFTER dayType
    `);
  }

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      id VARCHAR(36) PRIMARY KEY,
      userEmail VARCHAR(255) NOT NULL,
      userName VARCHAR(255) NOT NULL,
      status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
      tempPassword VARCHAR(255),
      timestamp VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX (userEmail)
    )
  `);

  await connection.execute(`
    CREATE TABLE IF NOT EXISTS custom_holidays (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_holiday (name, date)
    )
  `);

  console.log('Tables are ready.');
}

/**
 * A helper function to insert data into a table and handle duplicate entries.
 * @param {mysql.PoolConnection} connection - The database connection.
 * @param {string} tableName - The name of the table to insert into.
 * @param {Array<Object>} data - An array of objects to insert.
 * @param {string} primaryKey - The name of the primary key column (e.g., 'id' or 'email').
 */
async function insertData(connection, tableName, data, primaryKey = 'id') {
  if (!data || data.length === 0) {
    console.log(`No data to migrate for ${tableName}.`);
    return 0;
  }

  // Dynamically create the INSERT query
  const columns = Object.keys(data[0]);
  const sql = `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES ?`;
  const values = data.map(item => columns.map(col => item[col]));

  console.log(`Migrating ${data.length} records into ${tableName}...`);

  try {
    const [result] = await connection.query(sql, [values]);
    console.log(`Successfully inserted ${result.affectedRows} records into ${tableName}.`);
    return result.affectedRows;
  } catch (error) {
    // If bulk insert fails (e.g., due to duplicates), try one by one.
    console.warn(`Bulk insert for ${tableName} failed. Trying individual inserts...`);
    let insertedCount = 0;
    for (const item of data) {
      const singleSql = `INSERT INTO ${tableName} SET ?`;
      try {
        await connection.query(singleSql, item);
        insertedCount++;
      } catch (singleError) {
        if (singleError.code === 'ER_DUP_ENTRY') {
          console.warn(`- Skipping duplicate entry in ${tableName} where ${primaryKey} = ${item[primaryKey]}`);
        } else {
          console.error(`- Failed to insert record into ${tableName}:`, singleError.message);
        }
      }
    }
    console.log(`Successfully inserted ${insertedCount} records individually into ${tableName}.`);
    return insertedCount;
  }
}

async function migrate() {
  let pool;
  try {
    // 1. Connect to the database
    console.log('Connecting to MySQL database...');
    pool = mysql.createPool(dbConfig);
    const connection = await pool.getConnection();
    console.log('Database connection successful.');

    // 2. Ensure tables exist
    await createTables(connection);

    // 3. Read the data.json file
    console.log('Reading data from data.json...');
    const jsonData = await fs.readFile('data.json', 'utf-8');
    const data = JSON.parse(jsonData);

    // 4. Hash passwords for users and pending users
    const saltRounds = 10;
    const hashedUsers = data.users ? await Promise.all(data.users.map(async (user) => ({
      ...user,
      password: await bcrypt.hash(user.password, saltRounds)
    }))) : [];

    const hashedPendingUsers = data.pendingUsers ? await Promise.all(data.pendingUsers.map(async (user) => ({
      ...user,
      password: await bcrypt.hash(user.password, saltRounds)
    }))) : [];

    // 5. Begin migration for each table
    await insertData(connection, 'pending_users', hashedPendingUsers, 'id');
    await insertData(connection, 'users', hashedUsers, 'id');
    await insertData(connection, 'logs', data.logs, 'id');
    await insertData(connection, 'holiday_requests', data.holidayRequests, 'id');
    await insertData(connection, 'leave_applications', data.leaveApplications, 'id');
    await insertData(connection, 'password_reset_requests', data.passwordResetRequests, 'id');

    connection.release();

    console.log('\n✅ Migration completed successfully!');

  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error('FATAL: `data.json` not found in the backend directory. Please make sure the file exists.');
    } else {
      console.error('An error occurred during the migration process:', error);
      if (error.code === 'ER_ACCESS_DENIED_ERROR') {
        console.error("\nHint: This error means the password in your .env file for DB_PASSWORD is incorrect for your MySQL 'root' user.");
      }
    }
    process.exit(1);
  } finally {
    // 4. Close the database connection
    if (pool) {
      await pool.end();
      console.log('Database pool closed.');
    }
  }
}

// Run the migration
if (require.main === module) {
  migrate();
}

module.exports = {
  createTables,
  migrate
};