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

def print_map(map, num=None):     #takes map as first arg, and then map number(num) as second arg
    '''
    Print the map with terrain and resources
    '''
    if num is not None:     #prints map number if provided
        print(f"Map {num}:")
    for line in map:
        symbols = []        #empty list to append to 
        for tile in line:
            symbols.append(terrain_symbol(tile))
        print(" ".join(symbols))
    print()     #newline for space

#(map, res=None):
   # pass

#initiliaze dictionary for costs of traversing different terrains
terrain_costs = {
    Terrain.base: 0,      #1 base tile always in 0,0
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
    [5, 4, 2, 3, 2]
]

#list of resources to collect for map_1
resource_list_1 = {
    "stone": [(0,2), (2,1), (3,4)],  #list of where the 3 stones are in the map
    "iron": [(1,4), (4,0)],    #list of where the 2 irons are in the map
    "crystal": [(1,2)]   #list of where the 1 crystal is in the map
}

print_map(map_1, 1)