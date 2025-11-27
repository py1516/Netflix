import streamlit as st
import pandas as pd
import numpy as np
import altair as alt

st.title("Netflix Recommendation System Dashboard")

# Streamlit local storage using session_state
if "cleaned_df" not in st.session_state:
    st.session_state.cleaned_df = None

uploaded_file = st.file_uploader("Upload your Netflix CSV dataset", type=["csv"])

def clean_data(df):
    df = df.drop_duplicates()
    df = df.dropna()
    return df

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    cleaned = clean_data(df)
    st.session_state.cleaned_df = cleaned
    st.success("Data cleaned and stored in local session!")

if st.session_state.cleaned_df is not None:
    df = st.session_state.cleaned_df

    st.header("KPI Dashboard")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Titles", df.shape[0])
    col2.metric("Avg Rating", round(df["rating"].mean(), 2))
    col3.metric("Most Common Genre", df["genre"].mode()[0])

    st.header("Visualizations")

    genre_chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(x="genre", y="count()", color="genre")
    )
    st.altair_chart(genre_chart, use_container_width=True)

    rating_chart = (
        alt.Chart(df)
        .mark_line()
        .encode(x="release_year", y="mean(rating)")
    )
    st.altair_chart(rating_chart, use_container_width=True)