# db\database.py
import sqlite3
from config import DATABASE

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create users table
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    sql_commands = [
        """
        CREATE TABLE IF NOT EXISTS Users (
            user_id     INTEGER PRIMARY KEY,
            username    TEXT NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            isadmin     INTEGER DEFAULT 0
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Chat_Sessions (
            session_id  INTEGER PRIMARY KEY,
            user_id     INTEGER,
            name        TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            Description TEXT,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Chats (
            chat_id       INTEGER PRIMARY KEY,
            user_id       INTEGER,  
            session_id    INTEGER,
            user_message  TEXT,
            bot_response  TEXT,
            timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES Chat_Sessions(session_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Advisors (
            advisor_id    INTEGER PRIMARY KEY,
            name          TEXT NOT NULL,
            specialization TEXT,
            user_id       INTEGER,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Students (
            student_id INTEGER PRIMARY KEY,
            ssn        TEXT UNIQUE,
            major      TEXT,
            study_id   INTEGER,
            user_id    INTEGER,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Study_plan (
            study_id     INTEGER PRIMARY KEY,
            totalcredit  INTEGER,
            year         INTEGER
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Courses (
            course_id    INTEGER PRIMARY KEY,
            course_name  TEXT NOT NULL,
            description  TEXT,
            credithours  INTEGER,
            study_id     INTEGER,
            FOREIGN KEY (study_id) REFERENCES Study_plan(study_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Course_prerequisite (
            course_id INTEGER,
            pre_id    INTEGER,
            PRIMARY KEY (course_id, pre_id),
            FOREIGN KEY (course_id) REFERENCES Courses(course_id),
            FOREIGN KEY (pre_id) REFERENCES Courses(course_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Study_plan_details (
            study_id INTEGER,
            course_id INTEGER,
            status TEXT,
            PRIMARY KEY (study_id, course_id),
            FOREIGN KEY (study_id) REFERENCES Study_plan(study_id),
            FOREIGN KEY (course_id) REFERENCES Courses(course_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS student_enroll (
            student_id INTEGER,
            course_id INTEGER,
            grade TEXT,
            date TEXT,
            PRIMARY KEY (student_id, course_id),
            FOREIGN KEY (student_id) REFERENCES Students(student_id),
            FOREIGN KEY (course_id) REFERENCES Courses(course_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Time_Slots (
            slot_id       INTEGER PRIMARY KEY,
            advisor_id    INTEGER,
            available_date TEXT,
            time_slot    TEXT,
            is_booked    INTEGER DEFAULT 0,
            FOREIGN KEY (advisor_id) REFERENCES Advisors(advisor_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Appointments (
            appointment_id INTEGER PRIMARY KEY,
            student_id     INTEGER,
            slot_id        INTEGER,
            created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            advisor_id     INTEGER,
            timestamp      TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES Students(student_id),
            FOREIGN KEY (slot_id) REFERENCES Time_Slots(slot_id),
            FOREIGN KEY (advisor_id) REFERENCES Advisors(advisor_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Browse_Student (
            student_id INTEGER,
            brows_date TIMESTAMP,
            faq_id INTEGER,
            PRIMARY KEY (student_id, faq_id, brows_date),
            FOREIGN KEY (student_id) REFERENCES Students(student_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Browse_Adviser (
            advisor_id INTEGER,
            brows_date TIMESTAMP,
            faq_id INTEGER,
            PRIMARY KEY (advisor_id, faq_id,  brows_date),
            FOREIGN KEY (advisor_id) REFERENCES Advisors(advisor_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS It_staff (
            staff_id INTEGER PRIMARY KEY,
            permissions TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES Users(user_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Course_Update (
            update_id INTEGER PRIMARY KEY,
            course_id INTEGER,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            timestamp TIMESTAMP,
            description TEXT,
            FOREIGN KEY (course_id) REFERENCES Courses(course_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Student_Update (
            student_id INTEGER,
            update_id INTEGER,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            PRIMARY KEY (student_id, update_id),
            FOREIGN KEY (student_id) REFERENCES Students(student_id),
            FOREIGN KEY (update_id) REFERENCES Course_Update(update_id)
        );
        """
    ]

    for command in sql_commands:
        cursor.execute(command)

    conn.commit()
    conn.close()
    print("✅ Database schema initialized.")

def connect_db():
    conn = sqlite3.connect(DATABASE)
    return conn
