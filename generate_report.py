from jinja2 import Environment, FileSystemLoader

from report.conclusions import handy_conclusions
from report.get_top import get_top_red_ips


def generate_report(df, top10_analyze, filename):
    # --- dane ---
    honeypots = df[df["honeypot_field"] == "filled"]
    start = df["timestamp"].min()
    end = df["timestamp"].max()

    red_count = (df["risk_level"] == "RED_BLOCK").sum()
    orange_count = (df["risk_level"] == "ORANGE").sum()
    red_ip_percentage = round((red_count * 100) / len(df), 2)
    orange_ip_percentage = round((orange_count * 100) // len(df), 2)
    stats = {
        "file": filename,
        "records": len(df),
        "Unique_IPs": df["ip"].nunique(),
        "Unique_E_mails": df["email"].nunique(),
        "Unique_Countries": df["country"].nunique(),
        "Unique_User_Agents": df["user_agent"].nunique(),
        "Filled_honneypots": len(honeypots),
        "Period_of_time": f"{(end - start).days}",
        "red_count" : red_count,
        "orange_count": orange_count,
        "red_ip_percentage": red_ip_percentage,
        "orange_ip_percentage": orange_ip_percentage,

        }

    images = {
        "activity_first": "report/plots/activity_first_day.png",
        "activity": "report/plots/activity_over_time.png",
        "fill_time": "report/plots/fill_time_vs_spam.png",
        "score_distribution": "report/plots/score_distribution.png",
    }

    # zaladuj conlcusion z pliku jesli istnieje, jesli nie: wstaw domyslną wartosc
    conclusions = {"statistics": f"Analyzed period of {stats['Period_of_time']} days and {stats['records']} records, loaded from {stats['file']} file."}
    conclusions.update(handy_conclusions)

    top_10_ips = get_top_red_ips(df)

    # --- Jinja2 setup ---
    env = Environment(loader=FileSystemLoader("report/templates"))
    template = env.get_template("report.html")

    html = template.render(
        title="Network Traffic Data Analysis Report.",
        stats=stats,
        images=images,
        conclusions=conclusions,
        top_10_ips=top_10_ips,
        top10_analyze=top10_analyze
    )

    with open("complete_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("[OK] Generated report: complete_report.html")



def print_report(df):

    print("IP's:", df["ip"].nunique())
    print("Emails:", df["email"].nunique())
    print("Countries:", df["country"].nunique())
    print("User Agents:", df["user_agent"].nunique())

    honeypots = df[df["honeypot_field"] == "filled"]
    print("Honeypots:", len(honeypots))

    print(df["risk_level"].value_counts())

    top_ips = (
        df[df["risk_level"] == "RED_BLOCK"]["ip"]
        .value_counts()
        .head(10)
    )

    print(top_ips)
