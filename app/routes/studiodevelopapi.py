from flask import Blueprint, jsonify, request
from app.util import auth
from app.models.universe import Universe
from app.models.asset import Asset
from app.models.user import User

StudioDevelopAPIRoute = Blueprint("studiodevelopapi", __name__, url_prefix="/")

def _empty_page():
    return jsonify({"previousPageCursor": None, "nextPageCursor": None, "data": []})

@StudioDevelopAPIRoute.route("/v1/user/universes", methods=["GET"])
def studio_user_universes():
    CurrentUser : User = auth.GetCurrentUser()
    if CurrentUser is None:
        return _empty_page()

    Universes = Universe.query.filter_by(creator_id=CurrentUser.id, creator_type=0).order_by(Universe.id.desc()).all()
    Data = []
    for UniverseObj in Universes:
        RootAsset : Asset = Asset.query.filter_by(id=UniverseObj.root_place_id).first()
        Name = RootAsset.name if RootAsset is not None else f"Place {UniverseObj.root_place_id}"
        Data.append({
            "id": UniverseObj.id,
            "name": Name,
            "description": "",
            "isArchived": False,
            "rootPlaceId": UniverseObj.root_place_id,
            "isActive": True,
            "privacyType": "Public" if UniverseObj.is_public else "Private",
            "creatorType": "User",
            "creatorTargetId": UniverseObj.creator_id,
            "creatorName": CurrentUser.username,
            "created": UniverseObj.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "updated": UniverseObj.updated_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        })

    return jsonify({"previousPageCursor": None, "nextPageCursor": None, "data": Data})

@StudioDevelopAPIRoute.route("/v1/gametemplates", methods=["GET"])
def studio_gametemplates():
    return jsonify({"data": []})

@StudioDevelopAPIRoute.route("/v1/user/teamcreate/memberships", methods=["GET"])
def studio_teamcreate_memberships():
    return _empty_page()

@StudioDevelopAPIRoute.route("/v1/user/groups/canmanage", methods=["GET"])
def studio_groups_canmanage():
    return jsonify({"data": []})
