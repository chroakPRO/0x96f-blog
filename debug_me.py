#!/usr/bin/env python3

import sys

def calculate_average(numbers):
    total = 0
    count = 0
    
    for num in numbers:
        total += num
        count += 1
    
    # Bug: division by zero possible
    average = total / count
    return average

def process_data():
    data = [1, 2, 3, 4, 5]
    
    # Bug: modifying list while iterating
    for i, item in enumerate(data):
        if item % 2 == 0:
            data.remove(item)
    
    return data

def main():
    print("Debug example starting...")
    
    # Set breakpoint here for debugging
    import pdb; pdb.set_trace()
    
    # Test with valid data
    numbers = [10, 20, 30, 40]
    avg = calculate_average(numbers)
    print(f"Average: {avg}")
    
    # Test with empty list (will cause error)
    empty_list = []
    try:
        avg2 = calculate_average(empty_list)
        print(f"Empty average: {avg2}")
    except ZeroDivisionError as e:
        print(f"Error: {e}")
    
    # Process data with bugs
    result = process_data()
    print(f"Processed data: {result}")
    
    print("Debug example completed")

if __name__ == "__main__":
    main()