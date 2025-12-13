import sqlglot
from sqlglot import exp

schema = """
CREATE TABLE users (
    id INT PRIMARY KEY,
    name TEXT,
    email TEXT
);
CREATE TABLE orders (
    id INT PRIMARY KEY,
    user_id INT,
    amount DECIMAL,
    date DATE
);
"""

print("--- Parsing Schema ---")
parsed = sqlglot.parse(schema, read="sqlite")
for expression in parsed:
    print(f"Type: {type(expression)}")
    if isinstance(expression, exp.Create):
        print(f"Is Create: Yes")
        print(f"expression.this: {expression.this}")
        print(f"expression.this.name: {expression.this.name}")
        
        if expression.this.expressions:
            print("Columns:")
            for col_def in expression.this.expressions:
                if isinstance(col_def, exp.ColumnDef):
                    print(f" - {col_def.this.name}")
