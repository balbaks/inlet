from myapp.models import User


def get_user(user_id):
    return User.objects.raw(f"SELECT * FROM myapp_user WHERE id = {user_id}")


def get_user_extra(user_id):
    return User.objects.extra(where=[f"id = {user_id}"])
