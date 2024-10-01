Project Name : Auth Service for Multi tenant Saas - Backend Engineer

## Introduction
The project aims to demonstrate building a REST API with Flask.This is a multi-tenant authentication and user management service built using Flask for a Software as a Service (SaaS) platform. It provides functionalities such as user signup, login, password reset, inviting new members,role-based access control, and various statistics for role-wise and organization-wise user distributions.

## Features

 - User Signup: Users register with email, password, and organization info. Email alert sent upon  registration.
 - User Login: Users log in with email and password, receiving an email alert for security.
 - Password Reset: Users reset their password via email, with confirmation alert.
 - Invite Member: Admins invite users via email, assigning roles and organization ID.
 - Accept Invite: Invited users create accounts with invite token, email, and password.
 - Role Management: Admins manage user roles within the organization.
 - Statistics: Retrieve user stats by role, organization, with filtering options.

## Technologies

- Backend: Flask, Flask-SQLAlchemy, Flask-Migrate
- Database: PostgreSQL
- Authentication: Flask-JWT-Extended

## Routes

 - /signup (POST): Registers a new user and creates a new organization.
 - /signin (POST): Logs in an existing user.
 - /reset-password (POST): Resets the user's password.
 - /invite-member (POST): Sends an invite to a user to join an organization.
 - /accept-invite (GET): Allows invited users to accept and create an account.
 - /delete_member (DELETE): Removes a member from an organization.
 - /update_member_role (PUT): Updates a member's role in an organization.
 - /stats/role-wise-users (GET): Retrieves the number of users per role.
 - /stats/org-wise-members (GET): Retrieves the number of members per organization.
 - /stats/org-role-wise-users (GET): Retrieves organization-wise role-wise user counts.
 - /stats/org-role-wise-users-filtered (GET): Retrieves organization-wise role-wise user counts with date filtering.


->Installation and Setup

1. Clone the repository : git clone https://github.com/vinodkumarkuruva/Authorization.git

2.Prerequisites -  Python 3.12: Ensure that Python is installed on your system
                   Flask - As a Framework
 
3.Steps to Set Up -

   Create a virtual environment          :    python -m venv < name of virtual Environment > 
 	
   To activate the virtual Environment   :    < name of virtual Environment >/Scripts/activate 
 
   Install dependencies                  :    pip install -r requirements.txt
                                              pip install --upgrade flask-jwt-extended
 
   Set up the database                   :    flask db init
 	                                          flask db migrate -m "Initial migration"
                                              flask db upgrade
 
   Run the server                        :    Python run.py 
 
   * The application will start and be accessible at http://127.0.0.1:5000 with mentioned above endpoints.


4.Structure of the application

 /PF
 ├── Fusion/
 │   ├── models.py        		    # Contains the database models 
 │   ├── views.py         		    # Defines the API endpoints
 │   ├── __init__.py         		# Initializes the Flask app and SQLAlchemy
 ├── requirements.txt   			# Python dependencies         
 ├── migrations/        			# Directory for database migrations
 ├── app.py             			# Script for running the application             
 └── README.md              		# Project documentation

5.Other Info :

 -->The service uses Flask-Mail to send alerts for actions like login, signup, and password reset. Ensure that you configure your SMTP server credentials in the environment variables for sending emails.
 --> Error Handling: The application returns appropriate HTTP 400 status codes for Successful and bad requests.
 --> Modularity: The application is designed to be modular, with separate services handling business logic, making the codebase easy to maintain and extend.
 -->All APIs require data in JSON format. Some APIs, such as authentication, return a JWT token to be used in subsequent requests.
