import pandas as pd

# Read first 5 rows of the CSV with Latin-1 encoding
df = pd.read_csv('globalterrorismdb_0718dist.csv', nrows=10, encoding='latin1')

# Write to sample.txt with clean formatting
with open('sample.txt', 'w', encoding='utf-8') as f:
    # Write column names
    f.write("Column names:\n")
    f.write("\n".join(df.columns.tolist()))
    f.write("\n\nSample data:\n")
    
    # Write the data with proper formatting
    pd.set_option('display.max_columns', None)  # Show all columns
    pd.set_option('display.width', None)        # Don't wrap wide columns
    pd.set_option('display.max_colwidth', None) # Don't truncate column contents
    f.write(df.to_string()) 