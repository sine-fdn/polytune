CREATE DATABASE test;
USE test;

CREATE TABLE disability (
    id SERIAL PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    date_of_birth TEXT,
    care_level INT
);

LOAD DATA INFILE '/var/lib/mysql-files/disability.csv'
INTO TABLE disability
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
