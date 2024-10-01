from .models import User, Organization, Role, Member, Invite
from flask import request, jsonify
from Fusion import app, db, mail
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from passlib.hash import bcrypt
from flask_mail import Mail, Message
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
from datetime import datetime
import redis
import uuid
import threading
import logging
import time

# Initialize Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Function to send confirmation email
def send_alert(email):
    with app.app_context():
        msg = Message(
            'Registration Confirmation',
            sender='kuruvavinodkumar6529@gmail.com',  # Replace with your email
            recipients=[email]
        )
        msg.body = 'Thank you for registering! Please confirm your email address.'
        mail.send(msg)



# Function to process the email queue
def process_email_queue():
    while True:
        email_id = redis_client.lpop('email_queue')
        if email_id:
            # Retrieve email details
            email = redis_client.hget(f'email_status:{email_id}', 'email')
            if email:
                try:
                    send_alert(email)  # Send the email
                    # Update status to 'sent'
                    redis_client.hset(f'email_status:{email_id}', 'status', 'sent')
                    # print(f"Confirmation email sent to {email}")
                except Exception as e:
                    # Update status to 'failed' if an exception occurs
                    redis_client.hset(f'email_status:{email_id}', 'status', 'failed')
                    print(f"Failed to send email to {email}: {e}")
    time.sleep(2)  # Adjust this value to control how often the queue is checked

def start_email_sender():
    thread = threading.Thread(target=process_email_queue)
    thread.daemon = True  # Ensure thread exits when main program does
    thread.start()

# Start the email sender when the application starts
start_email_sender()

# Endpoint to check email status
@app.route('/email_status/<email_id>', methods=['GET'])
def get_email_status(email_id):
    status = redis_client.hgetall(f'email_status:{email_id}')
    if status:
        return jsonify({"email": status['email'], "status": status['status']}), 200
    else:
        return jsonify({"error": "Email ID not found."}), 404


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    organization_name = data.get('organization_name')
    role_name = data.get('role_name','owner')

    user = User.query.filter_by(email=email).first()
    
    if user:
        return jsonify({"error": "Email already registered! " }), 400

    if not email or not password or not organization_name:
        return jsonify({"msg": "Missing required fields"}), 400

    user = User(email=email, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    organization = Organization(name=organization_name)
    db.session.add(organization)
    db.session.commit()

    role = Role(name=role_name, description='Owner role', org_id=organization.id)
    db.session.add(role)
    db.session.commit()

    member = Member(org_id=organization.id, user_id=user.id, role_id=role.id)
    db.session.add(member)
    db.session.commit()

    email_id = str(uuid.uuid4())  # Unique ID for the email
    redis_client.rpush('email_queue', email_id)

    # Initialize email status in Redis
    redis_client.hset(f'email_status:{email_id}', mapping={
        'email': email,
        'status': 'pending'
    })


    return jsonify({"msg": "User and Organization created","email_id":email_id}), 201


@app.route('/signin', methods=['POST'])
def signin():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'msg': 'Missing required fields'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    # a = send_alert(email)

    return jsonify({"access_token": access_token, "refresh_token": refresh_token, "alert": a}), 200


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    if not email or not new_password:
        return jsonify({'msg': 'Missing required fields'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        # a = send_alert(email)
        return jsonify({'message': 'Password reset successful', 'alert': a}), 200
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/invite-member', methods=['POST'])
def invite_member():
    data = request.get_json()
    recipient = data.get('recipient')
    organization_id = data.get('organization_id')
    role_id = data.get('role_id')

    if not recipient or not organization_id or not role_id:
        return jsonify({'msg': 'Missing required fields'}), 400

    invite_token = str(uuid.uuid4())

    invite = Invite(email=recipient, token=invite_token, organization_id=organization_id, role_id=role_id)
    db.session.add(invite)
    db.session.commit()

    invite_link = f"http://localhost:5000/accept-invite?token={invite_token}"

    msg = Message("You're Invited!", recipients=[recipient])
    msg.body = f"Please use the following link to join the organization: {invite_link} or using token {invite_token}"

    try:
        mail.send(msg)
        return jsonify({'message': 'Invite email sent successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/accept-invite', methods=['GET'])
def accept_invite():
    
    data = request.get_json()
    token = data.get('token')
    email = data.get('email')
    password = data.get('password')

    if not token:
        return jsonify({'error': 'Token is required'}), 400

    invite = Invite.query.filter_by(token=token).first()

    if invite:
        user = User.query.filter_by(email=invite.email).first()
        if user:
            return jsonify({'error': 'Already Email is There.'}), 404
        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        member = Member(org_id=invite.organization_id, user_id=user.id, role_id=invite.role_id, status=0)
        db.session.add(member)
        db.session.delete(invite)
        db.session.commit()

        return jsonify({'message': 'Invite accepted successfully.'}), 200
    else:
        return jsonify({'error': 'Invalid or expired invite token.'}), 400


@app.route('/delete_member', methods=['DELETE'])
def delete_member():
    data = request.json
    org_id = data.get('org_id')
    user_id = data.get('user_id')

    if not org_id or not user_id:
        return jsonify({'msg': 'Missing required fields'}), 400

    member = Member.query.filter_by(org_id=org_id, user_id=user_id).first()
    if member:
        db.session.delete(member)
        db.session.commit()
        return jsonify({"msg": "Member deleted"}), 200
    return jsonify({"msg": "Member not found"}), 404


@app.route('/update_member_role', methods=['PUT'])
def update_member_role():
    data = request.get_json()
    member_id = data.get('member_id')
    new_role_id = data.get('role_id')

    if not member_id or not new_role_id:
        return jsonify({'error': 'Missing required fields'}), 400

    member = Member.query.get(member_id)
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    member.role_id = new_role_id
    db.session.commit()
    return jsonify({'message': 'Member role updated successfully.'}), 200


###########################################################################

#stats

# Role-wise number of users
@app.route('/stats/role-wise-users', methods=['GET'])
def role_wise_users():
    try:
        result = db.session.query(Role.name, db.func.count(Member.user_id)) \
            .join(Member, Role.id == Member.role_id) \
            .group_by(Role.name).all()

        return jsonify({role: count for role, count in result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Organization-wise number of members
@app.route('/stats/org-wise-members', methods=['GET'])
def org_wise_members():
    try:
        result = db.session.query(Organization.name, db.func.count(Member.user_id)) \
            .join(Member, Organization.id == Member.org_id) \
            .group_by(Organization.name).all()

        return jsonify({org: count for org, count in result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Organization-wise Role-wise Number of Users
@app.route('/stats/org-role-wise-users', methods=['GET'])
def org_role_wise_users():
    try:
        result = db.session.query(Organization.name, Role.name, db.func.count(Member.user_id)) \
            .join(Member, Organization.id == Member.org_id) \
            .join(Role, Role.id == Member.role_id) \
            .group_by(Organization.name, Role.name).all()

        stats = {}
        for org, role, count in result:
            if org not in stats:
                stats[org] = {}
            stats[org][role] = count

        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Organization-wise Role-wise Number of Users with Date Filtering
@app.route('/stats/org-role-wise-users-filtered', methods=['GET'])
def org_role_wise_users_filtered():
    from_time = request.args.get('from', type=int)
    to_time = request.args.get('to', type=int)

    try:
        query = db.session.query(Organization.name, Role.name, db.func.count(Member.user_id)) \
            .join(Member, Organization.id == Member.org_id) \
            .join(Role, Role.id == Member.role_id)

        if from_time:
            query = query.filter(Member.created_at >= datetime.fromtimestamp(from_time))

        if to_time:
            query = query.filter(Member.created_at <= datetime.fromtimestamp(to_time))

        query = query.group_by(Organization.name, Role.name)
        
        result = query.all()

        stats = {}
        for org, role, count in result:
            if org not in stats:
                stats[org] = {}
            stats[org][role] = count

        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
