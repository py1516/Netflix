import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# ---- STREAMLIT STORAGE ----
if "dataset" not in st.session_state:
    st.session_state.dataset = None

st.title("🎬 Netflix Recommendation & Analysis System")

st.write("Upload your dataset below to begin...")

# ---- FILE UPLOAD ----
uploaded_file = st.file_uploader("📁 Upload CSV Dataset", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # ---- DATA CLEANING ----
    st.subheader("🔧 Data Cleaning in Progress...")

    df.drop_duplicates(inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    # Save dataset to session_state (local mem storage)
    st.session_state.dataset = df

    st.success("Dataset cleaned and loaded successfully!")

# ---- DISPLAY DASHBOARD ----
if st.session_state.dataset is not None:
    df = st.session_state.dataset

    st.subheader("📊 Dataset Preview")
    st.dataframe(df.head())

    # ---- KPI ----
    st.subheader("📍 Key Metrics")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Titles", df.shape[0])
    with col2:
        st.metric("Unique Genres", df["Genre"].nunique())
    with col3:
        st.metric("Average Rating", round(df["IMDB_Rating"].mean(), 2))


    # ---- VISUALIZATIONS ----
    st.subheader("📈 Insights & Visuals")

    fig_genre = px.bar(df["Genre"].value_counts(), title="Content Count by Genre")
    st.plotly_chart(fig_genre)

    fig_rating = px.histogram(df, x="IMDB_Rating", nbins=20, title="Rating Distribution")
    st.plotly_chart(fig_rating)

    fig_year = px.line(df.groupby("Release_Year").size(), title="Titles Released per Year")
    st.plotly_chart(fig_year)


    # ---- Recommendation System ----
    st.subheader("🎯 Personalized Recommendation System")

    selected_genre = st.selectbox("Choose your favorite genre:", df["Genre"].unique())
    selected_rating = st.slider("Select minimum IMDb rating:", 1.0, 5.0, 3.5)

    recommendations = df[(df["Genre"] == selected_genre) & (df["IMDB_Rating"] >= selected_rating)]

    st.write(f"Recommended Titles ({len(recommendations)})👇")
    st.dataframe(recommendations[["Title", "Genre", "IMDB_Rating", "Release_Year"]].head(10))


else:
    st.info("Upload a CSV file to continue.")


