CREATE DATABASE test;
USE test;

CREATE TABLE insurance (
    id SERIAL PRIMARY KEY,
    name TEXT,
    status TEXT,
    address TEXT
);

LOAD DATA INFILE '/var/lib/mysql-files/insurance.csv'
INTO TABLE insurance
FIELDS TERMINATED BY ','
OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
