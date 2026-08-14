import pandas as pd

FILE = "final-complete-data-set.csv"

print("Loading dataset...")

df = pd.read_csv(FILE)

print("\n======================================")
print("DATASET INFORMATION")
print("======================================")

print("Rows    :", df.shape[0])
print("Columns :", df.shape[1])

print("\n======================================")
print("COLUMN NAMES")
print("======================================")

for i, column in enumerate(df.columns):
    print(f"{i}: {column}")

print("\n======================================")
print("FIRST 5 ROWS")
print("======================================")

print(df.head())

print("\n======================================")
print("DATA TYPES")
print("======================================")

print(df.dtypes)

print("\n======================================")
print("MISSING VALUES")
print("======================================")

print(df.isnull().sum())

print("\n======================================")
print("UNIQUE VALUES FOR POSSIBLE LABEL COLUMNS")
print("======================================")

for column in df.columns:

    if df[column].dtype == "object":

        unique_values = df[column].dropna().unique()

        if len(unique_values) <= 20:

            print(f"\n{column}:")
            print(unique_values)