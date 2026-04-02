from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models.models import User, Subscription, ScanUsage, Plan


def get_user_plan(db: Session, user_id: int) -> dict:
    subscription = db.query(Subscription).filter(
        Subscription.user_id == user_id,
        Subscription.status == "active"
    ).first()

    if not subscription:
        return {"name": "free", "scans_per_month": 10, "api_access": False}

    plan = subscription.plan
    return {
        "name": plan.name,
        "display_name": plan.display_name,
        "scans_per_month": plan.scans_per_month,
        "api_access": plan.api_access,
        "billing_cycle": subscription.billing_cycle,
        "period_end": subscription.current_period_end
    }


def get_scan_usage(db: Session, user_id: int) -> int:
    month = datetime.utcnow().strftime("%Y-%m")
    usage = db.query(ScanUsage).filter(
        ScanUsage.user_id == user_id,
        ScanUsage.month == month
    ).first()
    return usage.scan_count if usage else 0


def increment_scan_usage(db: Session, user_id: int):
    month = datetime.utcnow().strftime("%Y-%m")
    usage = db.query(ScanUsage).filter(
        ScanUsage.user_id == user_id,
        ScanUsage.month == month
    ).first()

    if usage:
        usage.scan_count += 1
    else:
        usage = ScanUsage(user_id=user_id, month=month, scan_count=1)
        db.add(usage)
    db.commit()


def check_scan_limit(db: Session, user_id: int):
    plan = get_user_plan(db, user_id)
    if plan["scans_per_month"] == -1:
        return True

    usage = get_scan_usage(db, user_id)
    if usage >= plan["scans_per_month"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "scan_limit_exceeded",
                "message": f"You have used all {plan['scans_per_month']} scans this month.",
                "upgrade_url": "/pricing"
            }
        )
    return True


def seed_plans(db: Session):
    if db.query(Plan).count() > 0:
        return

    plans = [
        Plan(
            name="free",
            display_name="Free",
            price_monthly=0,
            price_yearly=0,
            scans_per_month=10,
            api_access=False,
            multi_user=False
        ),
        Plan(
            name="pro",
            display_name="Pro",
            price_monthly=29,
            price_yearly=290,
            scans_per_month=-1,
            api_access=False,
            multi_user=False
        ),
        Plan(
            name="enterprise",
            display_name="Enterprise",
            price_monthly=99,
            price_yearly=990,
            scans_per_month=-1,
            api_access=True,
            multi_user=True
        ),
    ]

    for plan in plans:
        db.add(plan)
    db.commit()