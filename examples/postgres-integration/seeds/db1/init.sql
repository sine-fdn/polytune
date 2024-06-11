CREATE TABLE insurance (
    id SERIAL PRIMARY KEY,
    name TEXT,
    status TEXT,
    address TEXT
);

COPY insurance
FROM '/docker-entrypoint-initdb.d/insurance.csv'
DELIMITER ','
CSV HEADER;