import pandas as pd
import argparse

def jsonl_to_excel(jsonl_path: str, excel_path: str, chunksize: int = 50000):
    """
    Reads a large JSONL file in chunks and writes it into a single Excel sheet.
    
    Parameters:
    - jsonl_path: path to the .jsonl file
    - excel_path: output .xlsx file path
    - chunksize: how many lines to read into memory at once
    """
    # Create the Excel writer using openpyxl (installed with pandas >=1.2)
    writer = pd.ExcelWriter(excel_path, engine='openpyxl')
    startrow = 0
    
    # Read the JSONL in chunks
    for i, chunk in enumerate(pd.read_json(jsonl_path, lines=True, chunksize=chunksize)):
        # For the first chunk, include headers; thereafter omit them
        header = (i == 0)
        
        # Write to the same sheet, starting at the correct row
        chunk.to_excel(
            writer,
            sheet_name='Sheet1',
            index=False,
            header=header,
            startrow=startrow
        )
        
        # Update row counter: chunk.shape[0] rows + 1 header row (only once)
        startrow += chunk.shape[0] + (1 if header else 0)
        print(f"  • Written chunk {i+1}, rows so far: {startrow}")
    
    writer.save()
    print(f"\n✅ Finished! Excel file saved at: {excel_path}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Convert a large JSONL file into a single-sheet Excel workbook"
    )
    p.add_argument("jsonl_path", help="Path to your .jsonl file")
    p.add_argument("excel_path", help="Where to write the .xlsx file")
    p.add_argument(
        "--chunksize", type=int, default=50000,
        help="Number of lines to read into memory at once (default: 50 000)"
    )
    args = p.parse_args()
    jsonl_to_excel(args.jsonl_path, args.excel_path, args.chunksize)
