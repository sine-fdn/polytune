CREATE TABLE early_detection_screening (
    id SERIAL PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    date_of_birth TEXT,
    screening_status TEXT
);

COPY early_detection_screening
FROM '/docker-entrypoint-initdb.d/early_detection_screening.csv'
DELIMITER ','
CSV HEADER;