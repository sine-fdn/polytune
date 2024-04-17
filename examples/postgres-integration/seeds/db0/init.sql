CREATE TABLE residents (
    id SERIAL PRIMARY KEY,
    name TEXT,
    age INT,
    address TEXT
);

COPY residents
FROM '/docker-entrypoint-initdb.d/residents.csv'
DELIMITER ','
CSV HEADER;