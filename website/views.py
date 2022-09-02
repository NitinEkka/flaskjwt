from crypt import methods
from dataclasses import dataclass
from flask import Blueprint, render_template, request, flash, jsonify , redirect, url_for
from flask_login import login_required, current_user
from .models import Note, User
from . import db
import json
from werkzeug.security import check_password_hash
from . import token_required

views = Blueprint('views', __name__)


@views.route('/', methods=['GET','POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')
        
        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')    


   
    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods=['POST'])
@token_required
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

@views.route('/delete-account', methods['POST'])
@token_required
def delete_acc():
       if request.method=='POST':
            email = request.form.get('email')
            firstName = request.form.get('firstName')
            password = request.form.get('password1')
            
            user = User.query.filter_by(email=email).first()
            
            if user:
                if firstName != user.firstName:
                    flash('Name does not match', category='error')
                elif check_password_hash(user.password, password):
                    flash('Password does not match', category='error')
                else:
                    db.session.delete(user)
                    db.session.commit()
            else:
                flash('User not found', category='error')        
                return redirect(url_for(views.home))
            
            
            return render_template('delete.html')


            
                    


