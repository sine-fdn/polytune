CREATE TABLE insurance (
    id SERIAL PRIMARY KEY,
    name TEXT,
    disabled BOOL,
    address TEXT
);

COPY insurance
FROM '/docker-entrypoint-initdb.d/insurance.csv'
DELIMITER ','
CSV HEADER;