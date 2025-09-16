#map generator file

'''Quest Objective
Gather the following resources and return them to the base:
• 3 × Stone
• 2 × Iron
• 1 × Crystal'''

#initiliaze dictionary for costs of traversing different terrains
terrain_costs = {"empty": 0,    #for simplicity, 5 empty tiles  
                "base": 0,      #1 base tile always in 0,0
                "grasslands": 1,    #5 grassland tiles
                "hills": 2,         #5 hill tiles
                "swamps": 3,        #5 swamp tiles
                "mountains": 4}     #4 mountain tiles

#representation of the first map
map_1 = [['base', 'mountains', 'empty', 'grasslands', 'mountains'],
        ['hills', 'empty', 'swamps', 'empty', 'grasslands'],
        ['empty', 'swamps', 'empty', 'hills', 'hills'],
        ['grasslands', 'swamps', 'mountains', 'swamps', 'hills'],
        ['mountains', 'swamps', 'grasslands', 'hills', 'grasslands']]

#list of resources to collect for map_1
resource_list_1 = {"stone": [],  #list of where the 3 stones are in the map
                    "iron": [],    #list of where the 2irons are in the map
                    "crystal": []   #list of where the 1 crystal is in the map
}