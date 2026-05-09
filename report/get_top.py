def get_top_red_ips(df):
    return (
        df[df["risk_level"] == "RED_BLOCK"]["ip"]
        .value_counts()
        .head(10)
    )

