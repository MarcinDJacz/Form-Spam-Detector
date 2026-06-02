import argparse
import time
from datetime import datetime, timedelta
from pathlib import Path
import matplotlib.dates as mdates
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from analyze_ip import analyze_ip_list
from generate_report import generate_report
from report.get_top import get_top_red_ips

MAX_GREEN = 20
MAX_ORANGE = 100
MAX_RED_REVIEW = 150

def classify(score):
    if score > MAX_RED_REVIEW:
        return "RED_BLOCK"
    if score > MAX_ORANGE:
        return "RED_REVIEW"
    elif score >= MAX_GREEN:
        return "ORANGE"
    return "GREEN"

def load_data(file_path):
    if not Path(file_path).exists():
        print("Plik nie istnieje")
        return None

    return pd.read_csv(file_path, parse_dates=["timestamp"])

def filter_by_date(df, since, to):
    if since and to and since > to:
        print("Błąd: --since nie może być późniejsze niż --to")
        return None

    if since:
        df = df[df["timestamp"] >= since]

    if to:
        df = df[df["timestamp"] < (to + timedelta(days=1))]

    return df

def add_features_and_score(df):
    df["flag_honeypot"] = df["honeypot_field"] == "filled"
    df["flag_bot_ua"] = df["user_agent"].str.contains(
        "python-requests|SEObot",
        na=False
    )
    df["flag_fast_submit"] = df["form_fill_time_sec"] < 3

    df["score"] = 0

    df.loc[df["flag_honeypot"], "score"] += 100
    df.loc[df["flag_bot_ua"], "score"] += 70
    df.loc[df["flag_fast_submit"], "score"] += 20

    df["risk_level"] = df["score"].apply(classify)

    return df


def plot_score_distribution(df):
    score_counts = df["score"].value_counts().sort_index()

    plt.figure(figsize=(12, 5))

    colors = [
        "green" if x < MAX_GREEN else
        "orange" if x < MAX_ORANGE else
        "red"
        for x in score_counts.index
    ]

    plt.bar(
        score_counts.index,
        score_counts.values,
        color=colors,
        width=1.0
    )

    plt.title("Score distribution (exact values)")
    plt.xlabel("Score")
    plt.ylabel("Number of records")

    plt.grid(True, axis="y", alpha=0.3)
    plt.xticks(range(0, max(score_counts.index) + 1, 10))
    legend_elements = [
        Patch(facecolor="green", label=f"Safe (< {MAX_GREEN})"),
        Patch(facecolor="orange", label=f"False alarm / Suspicious ({MAX_GREEN}-{MAX_ORANGE - 1})"),
        Patch(facecolor="red", label=f"Likely spam (>= {MAX_ORANGE})")
    ]

    plt.legend(handles=legend_elements)
    plt.savefig("report/plots/score_distribution.png", dpi=300, bbox_inches="tight")
    plt.close()

def plot_fill_time_vs_spam(df):
    RED_MAX_FILL_TIME = 5
    ORAGNE_MAX_FILL_TIME = 10
    fill_time_counts = df["form_fill_time_sec"].value_counts().sort_index()

    plt.figure(figsize=(12, 5))

    colors = [
        "red" if x < RED_MAX_FILL_TIME else
        "orange" if x < ORAGNE_MAX_FILL_TIME else
        "green"
        for x in fill_time_counts.index
    ]
    plt.bar(
        fill_time_counts.index,
        fill_time_counts.values,
        color=colors,
        width=1.0
    )
    plt.title("Fill time distribution (exact values)")
    plt.xlabel("Fill time")
    plt.ylabel("Number of records")

    plt.grid(True, axis="y", alpha=0.3)
    plt.xticks(range(0, max(fill_time_counts.index) + 1, 50))

    legend_elements = [
        Patch(facecolor="red", label=f"Likely spam (< {RED_MAX_FILL_TIME}s.)"),
        Patch(facecolor="orange", label=f"Suspicious:({RED_MAX_FILL_TIME}-{ORAGNE_MAX_FILL_TIME}s.)"),
        Patch(facecolor="green", label=f"Safe (>= {ORAGNE_MAX_FILL_TIME}s.)")
    ]

    plt.legend(handles=legend_elements)

    plt.savefig("report/plots/fill_time_vs_spam.png", dpi=300, bbox_inches="tight")
    plt.close()

def plot_activity_over_time(df):
    activity = df.set_index("timestamp").resample("h").size()

    plt.figure(figsize=(12,5))
    colors = [
        "red" if x > 100 else
        "orange" if x > 50 else
        "green"
        for x in activity.values
    ]
    plt.bar(
        activity.index,
        activity.values,
        color=colors,
        width=0.03
    )
    plt.title("Activity over time")
    plt.xlabel("Time")
    plt.ylabel("Number of submissions")

    plt.grid(True, axis="y", alpha=0.3)
    plt.xticks(rotation=45)
    plt.savefig("report/plots/activity_over_time.png", dpi=300, bbox_inches="tight")
    plt.close()

def plot_activity_over_last_6_days(df):
    df = df[
        df["timestamp"] >=
        df["timestamp"].max() - pd.Timedelta(days=6)
    ]

    activity = (
        df.set_index("timestamp")
        .resample("h")
        .size()
        .rename("count")
        .to_frame()
    )

    activity["hour"] = activity.index.hour

    hourly_stats = (
        activity.groupby("hour")["count"]
        .agg(["mean", "std"])
        .fillna(0)
    )

    activity["mean"] = activity["hour"].map(hourly_stats["mean"])
    activity["std"] = activity["hour"].map(hourly_stats["std"])

    activity["upper"] = activity["mean"] + 2 * activity["std"]
    activity["lower"] = (activity["mean"] - 2 * activity["std"]).clip(lower=0)

    anomalies = activity[activity["count"] > activity["upper"]]

    colors = [
        "red" if val > upper else
        "orange" if val > mean else
        "green"
        for val, upper, mean in zip(
            activity["count"],
            activity["upper"],
            activity["mean"]
        )
    ]

    plt.figure(figsize=(14, 6))

    plt.bar(
        activity.index,
        activity["count"],
        color=colors,
        width=0.03,
        label="Activity"
    )

    plt.plot(activity.index, activity["mean"], linewidth=2, label="Hourly mean")

    plt.fill_between(
        activity.index,
        activity["lower"],
        activity["upper"],
        alpha=0.2,
        label="Normal range (±2 std)"
    )

    plt.scatter(anomalies.index, anomalies["count"], s=40, label="Anomaly")

    # 1. X-axis: tylko godziny, co 3h
    plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=4))
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    # 2. Linie pionowe = zmiana dnia
    days = activity.index.normalize().unique()
    for day in days:
        plt.axvline(day, color="gray", linestyle="--", alpha=0.3)

    plt.title("Activity over time with anomaly detection")
    plt.xlabel("Hour of day")
    plt.ylabel("Number of submissions")

    plt.grid(True, axis="y", alpha=0.3)
    plt.xticks(rotation=90)

    plt.legend()

    plt.savefig(
        "report/plots/activity_over_last_6_days.png",
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()


def plot_activity_first_day(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")

    # 1. wyciągamy pierwszy dzień z danych
    first_day = df["timestamp"].dt.date.min()
    df_day = df[df["timestamp"].dt.date == first_day]

    # 2. resample co 30 minut
    activity = (
        df_day.set_index("timestamp")
        .resample("30min")
        .size()
    )

    # 3. kolorowanie
    colors = [
        "red" if x > 100 else
        "orange" if x > 50 else
        "green"
        for x in activity.values
    ]

    # 4. wykres
    plt.figure(figsize=(12,5))
    plt.bar(activity.index, activity.values, color=colors, width=0.02)

    plt.title(f"Activity on {first_day}")
    plt.xlabel("Time")
    plt.ylabel("Number of submissions")

    plt.grid(True, axis="y", alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("report/plots/activity_first_day.png", dpi=300, bbox_inches="tight")
    plt.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("file")

    parser.add_argument(
        "--since",
        type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
    )

    parser.add_argument(
        "--to",
        type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
    )

    args = parser.parse_args()
    t1 = time.time()
    df = load_data(args.file)
    if df is None:
        return
    filename = Path(args.file).name
    df = filter_by_date(df, args.since, args.to)
    if df is None or df.empty:
        print("Brak danych.")
        return
    t2 = time.time()
    print(f"[OK] Loaded {len(df)} records in {t2-t1:.3f}s")

    df = add_features_and_score(df)

    t3 = time.time()
    print(f"[OK] Analysis completed in {t3 - t2:.3f}s")

    plot_score_distribution(df)
    plot_fill_time_vs_spam(df)
    plot_activity_over_time(df)
    plot_activity_first_day(df)
    plot_activity_over_last_6_days(df)

    t4 = time.time()
    print(f"[OK] Generated 5 plots in {t4 - t3:.3f}s")

    top_10_ips = get_top_red_ips(df)
    list = top_10_ips.index.tolist()
    top10_analyze = analyze_ip_list(list)

    t5 = time.time()
    print(f"[OK] Analyzed RED FLAG IPs through API in {t5-t4}s.")
    generate_report(df, top10_analyze, filename)

    t6 = time.time()
    print(f"[OK] Created HTML report in {t6-t5:.3f}s.")
    print('-----------------------------------')
    print(f"[DONE] Finished in {t6-t1:.3f}s.")

if __name__ == "__main__":
    main()
