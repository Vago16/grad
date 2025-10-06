#map generator file

from enum import IntEnum


#initialize class for terrain using enum
class Terrain(IntEnum):
    base = 0
    empty = 1
    grasslands = 2
    hills = 3
    swamps = 4
    mountains = 5

#function for help with printing out map
def terrain_symbol(t: Terrain):   #t is the argument for terrain symbol(a single character)
    symbols = {
        Terrain.base: "B",
        Terrain.empty: ".",
        Terrain.grasslands: "G",
        Terrain.hills: "H",
        Terrain.swamps: "S",
        Terrain.mountains: "M"
        }
    return symbols[t]

def print_map(map, num=None):     #takes map as first arg and then map number(num) as second arg
    '''
    Print the map with terrain.
    '''

    if num is not None:     #prints map number if provided
        print(f"Map {num}:")
    for line in map:
        symbols = []        #empty list to append to, to print to terminal
        for tile in line:
            symbols.append(terrain_symbol(tile))
        print(" ".join(symbols))
    print()     #newline for space

def print_resource_list(resource_list, num=None):   #takes resource list as first arg and then map number(num) as second arg
    '''
    Print resource list for a given map.
    '''
    
    if num is not None:     #prints map number for resource list if provided
        print(f"Map {num} resource list:")

    for resource, coordinate in resource_list.items():      #gets the tuple of the key-value pairs from the dicitonary
        print(f"{resource}: {coordinate}")

    print() #newline for space


#initiliaze dictionary for costs of traversing different terrains
#this shows additional costs of traversing terrain
#any tiles that may have been in (4,4) are now replaced by a base
terrain_costs = {
    Terrain.base: 0,      #2 base tiles always in 0,0 and (4,4)
    Terrain.empty: 0,    #for simplicity, 5 empty tiles  
    Terrain.grasslands: 1,    #5 grassland tiles
    Terrain.hills: 2,         #5 hill tiles
    Terrain.swamps: 3,        #5 swamp tiles
    Terrain.mountains: 4}     #4 mountain tiles

#2-D array representation of the first map
map_1 = [
    [0, 5, 1, 2, 5],
    [3, 1, 4, 1, 2],
    [1, 4, 1, 3, 3],
    [2, 4, 5, 4, 3],
    [5, 4, 2, 3, 0]
]

#2-D array representation of the first map
map_2 = [
    [0, 1, 4, 5, 5],
    [1, 1, 4, 4, 3],
    [4, 4, 1, 2, 3],
    [5, 3, 2, 1, 2],
    [5, 3, 3, 2, 0]
]

#simple straightforward map mainly for testing to make sure search alg works 
map_3 = [
    [0, 1, 1, 1, 1],
    [5, 5, 5, 5, 1],
    [4, 4, 4, 4, 2],
    [4, 2, 2, 3, 2],
    [3, 3, 3, 3, 0]
]

#list of resources to collect for map_1
resource_list_1 = {
    "Stone": [(0,2), (2,1), (3,4)],  #list of where the 3 stones are in the map
    "Iron": [(1,4), (4,0)],    #list of where the 2 irons are in the map
    "Crystal": [(1,2)]   #list of where the 1 crystal is in the map
}

#list of resources to collect for map_2
resource_list_2 = {
    "Stone": [(1,1), (2,2), (3,3)],  #list of where the 3 stones are in the map
    "Iron": [(2,4), (4,2)],    #list of where the 2 irons are in the map
    "Crystal": [(4,0)]   #list of where the 1 crystal is in the map
}

#list of resources to collect for map_3
resource_list_3 = {
    "Stone": [(0,1), (0,2), (0,3)],  #list of where the 3 stones are in the map
    "Iron": [(0,4), (1,4)],    #list of where the 2 irons are in the map
    "Crystal": [(2,4)]   #list of where the 1 crystal is in the map
}

