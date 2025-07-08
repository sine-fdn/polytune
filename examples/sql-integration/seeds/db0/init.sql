CREATE TABLE location_town (
    id SERIAL PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    date_of_birth TEXT,
    screening_status TEXT
);

COPY location_town
FROM '/docker-entrypoint-initdb.d/location_town.csv'
DELIMITER ','
CSV HEADER;