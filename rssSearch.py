import json
import sys

def find_rss_item(json_data, field, value, exact=True):
    """
    Generic RSS item finder
    
    Args:
        json_data: The converted JSON data from RSS feed
        field: Field to search in (e.g., 'guid', 'title', 'link', 'pubDate')
        value: Value to search for
        exact: True for exact match, False for partial match
    
    Returns:
        Found item dict or None
    
    Usage examples:
        item = find_rss_item(json_data, "guid", "unique-id-1")
        item = find_rss_item(json_data, "title", "Article", exact=False)
        item = find_rss_item(json_data, "link", "https://example.com/article1")
        item = find_rss_item(json_data, "pubDate", "2025", exact=False)
    """
    try:
        items = json_data["rss"]["channel"]["item"]
        
        # Handle single item (sometimes RSS has only one item as dict, not list)
        if isinstance(items, dict):
            items = [items]
        
        for item in items:
            item_value = item.get(field, "")
            if exact:
                if item_value == value:
                    return item
            else:
                if str(value).lower() in str(item_value).lower():
                    return item
        return None
    except KeyError:
        print(f"RSS structure not found. Available keys: {list(json_data.keys())}")
        return None

def find_all_rss_items(json_data, field, value, exact=True):
    """
    Find ALL RSS items matching criteria (not just the first one)
    
    Returns:
        List of matching items
    """
    try:
        items = json_data["rss"]["channel"]["item"]
        
        # Handle single item case
        if isinstance(items, dict):
            items = [items]
        
        found_items = []
        for item in items:
            item_value = item.get(field, "")
            if exact:
                if item_value == value:
                    found_items.append(item)
            else:
                if str(value).lower() in str(item_value).lower():
                    found_items.append(item)
        return found_items
    except KeyError:
        print(f"RSS structure not found. Available keys: {list(json_data.keys())}")
        return []

def get_all_rss_items(json_data):
    """Get all RSS items as a list"""
    try:
        items = json_data["rss"]["channel"]["item"]
        if isinstance(items, list):
            return items
        elif isinstance(items, dict):
            return [items]
        return []
    except KeyError:
        print(f"RSS structure not found. Available keys: {list(json_data.keys())}")
        return []

def print_item_summary(item, index=None):
    """Print a nice summary of an RSS item"""
    prefix = f"[{index}] " if index is not None else ""
    
    title = item.get("title", "No Title")
    guid = item.get("guid", "No GUID")
    link = item.get("link", "No Link")
    pub_date = item.get("pubDate", "No Date")
    
    print(f"{prefix}Title: {title}")
    print(f"     GUID: {guid}")
    print(f"     Link: {link}")
    print(f"     Date: {pub_date}")
    print("-" * 60)

def main():
    # Get JSON filename
    if len(sys.argv) > 1:
        json_file = sys.argv[1]
    else:
        json_file = input("Enter JSON filename: ")
    
    # Load JSON data
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {json_file}")
        return
    except json.JSONDecodeError:
        print(f"Invalid JSON file: {json_file}")
        return
    
    print(f"Loaded RSS data from: {json_file}")
    print("=" * 60)
    
    # Show all items first
    all_items = get_all_rss_items(json_data)
    print(f"Total RSS items: {len(all_items)}")
    print("=" * 60)
    
    print("ALL RSS ITEMS:")
    for i, item in enumerate(all_items, 1):
        print_item_summary(item, i)
    
    # Interactive search
    while True:
        print("\n" + "=" * 60)
        print("SEARCH OPTIONS:")
        print("1. Search by field")
        print("2. Show all items again")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            print("\nAvailable fields to search:")
            print("- title")
            print("- guid") 
            print("- link")
            print("- pubDate")
            print("- description (if available)")
            
            field = input("\nEnter field to search: ").strip()
            value = input("Enter search value: ").strip()
            exact_input = input("Exact match? (y/n) [n]: ").strip().lower()
            exact = exact_input == 'y'
            
            # Find all matching items
            found_items = find_all_rss_items(json_data, field, value, exact)
            
            print(f"\n--- SEARCH RESULTS ---")
            print(f"Searching for '{value}' in field '{field}' (exact={exact})")
            print(f"Found {len(found_items)} item(s):")
            print("-" * 60)
            
            if found_items:
                for i, item in enumerate(found_items, 1):
                    print_item_summary(item, i)
            else:
                print("No items found matching your criteria.")
        
        elif choice == "2":
            print("\nALL RSS ITEMS:")
            for i, item in enumerate(all_items, 1):
                print_item_summary(item, i)
        
        elif choice == "3":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    print("RSS Search Demo")
    print("This script demonstrates how to search through RSS JSON data")
    print("=" * 60)
    main()
