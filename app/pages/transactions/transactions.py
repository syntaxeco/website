from flask import Blueprint, render_template, request, redirect, url_for, session, flash, redirect, make_response, abort
from datetime import datetime, timedelta

from app.models.user_transactions import UserTransaction
from app.util import auth
from app.extensions import db
from app.models.user import User
from app.models.groups import Group
from app.models.asset import Asset
from app.enums.TransactionType import TransactionType

TransactionsRoute = Blueprint('transactions', __name__, url_prefix='/transactions')

CategoryToEnum = {
    "purchase": TransactionType.Purchase,
    "sale": TransactionType.Sale,
    "group-payout": TransactionType.GroupPayout,
    "stipends": TransactionType.BuildersClubStipend,
}

def GetCounterpartyName( EntityId : int, EntityType : int ) -> str:
    """Display name for a transaction counterparty, tolerating deleted users/groups."""
    if EntityType == 1:
        GroupObj : Group = Group.query.filter_by(id=EntityId).first()
        return GroupObj.name if GroupObj is not None else "Deleted group"
    UserObj : User = User.query.filter_by(id=EntityId).first()
    return UserObj.username if UserObj is not None else "Deleted user"

@TransactionsRoute.route("/", methods=["GET"])
@auth.authenticated_required
def TransactionsPage():
    AuthenticatedUser : User = auth.GetCurrentUser()

    CategoryArg = request.args.get('category', default="purchase", type=str)
    if CategoryArg not in CategoryToEnum:
        Category : TransactionType = TransactionType.Purchase
    else:
        Category : TransactionType = CategoryToEnum[CategoryArg]
        
    PageNumber = request.args.get('page', default=1, type=int)
    if PageNumber < 1:
        PageNumber = 1

    TransactionQuery = UserTransaction.query.filter_by( transaction_type = Category)
    CategoryQueryDict = {
        TransactionType.Purchase: lambda queryObj: queryObj.filter_by(
            sender_id = AuthenticatedUser.id,
            sender_type = 0
        ),
        TransactionType.Sale: lambda queryObj: queryObj.filter_by(
            reciever_id = AuthenticatedUser.id,
            reciever_type = 0
        ),
        TransactionType.GroupPayout: lambda queryObj: queryObj.filter_by(
            reciever_id = AuthenticatedUser.id,
            reciever_type = 0
        ),
        TransactionType.BuildersClubStipend: lambda queryObj: queryObj.filter_by(
            reciever_id = AuthenticatedUser.id,
            reciever_type = 0
        ),
    }
    TransactionQuery = CategoryQueryDict[Category](TransactionQuery)
    TransactionQuery = TransactionQuery.order_by(UserTransaction.created_at.desc())
    TransactionQuery = TransactionQuery.paginate( page=PageNumber, per_page=15, error_out=False )

    FormattedTransactions = []
    for Transaction in TransactionQuery.items:
        Transaction : UserTransaction = Transaction
        TransactionInfo = {}
        IsOutgoing = Transaction.sender_id == AuthenticatedUser.id and Transaction.sender_type == 0
        CounterpartyId = Transaction.reciever_id if IsOutgoing else Transaction.sender_id
        CounterpartyType = Transaction.reciever_type if IsOutgoing else Transaction.sender_type
        TransactionInfo["source"] = {
            "id": CounterpartyId,
            "type": CounterpartyType,
            "name": GetCounterpartyName(CounterpartyId, CounterpartyType),
        }
        TransactionInfo["currency_amount"] = Transaction.currency_amount
        TransactionInfo["currency_type"] = Transaction.currency_type
        TransactionInfo["created_at"] = Transaction.created_at.strftime("%d/%m/%Y %H:%M:%S UTC")
        TransactionInfo["custom_text"] = Transaction.custom_text
        if Transaction.assetId:
            AssetObj : Asset = Asset.query.filter_by(id = Transaction.assetId).first()
            TransactionInfo["asset"] = {
                "id": Transaction.assetId,
                "name": AssetObj.name if AssetObj is not None else "Deleted item",
            }
        else:
            TransactionInfo["asset"] = None
        FormattedTransactions.append(TransactionInfo)

    return render_template(
        "transactions/transactions.html",
        PageCategory = CategoryArg,
        TransactionInfo = FormattedTransactions,
        Pagination = TransactionQuery
    )