-- Run these in Access (Create > Query Design > SQL View), then Run:
CREATE TABLE People (
    ID AUTOINCREMENT CONSTRAINT PK_People PRIMARY KEY,
    FirstName TEXT(50) NOT NULL,
    LastName  TEXT(50) NOT NULL,
    Age LONG
);
CREATE INDEX IX_People_Name ON People (LastName, FirstName);

-- Optional seed data:
INSERT INTO People (FirstName, LastName, Age) VALUES ('Ada','Lovelace',36);
INSERT INTO People (FirstName, LastName, Age) VALUES ('Alan','Turing',41);
INSERT INTO People (FirstName, LastName, Age) VALUES ('Grace','Hopper',85);
