#Heuristic for the search algorithm

#admissible heuristic function, used https://www.geeksforgeeks.org/artificial-intelligence/heuristic-function-in-ai/ for help in understanding further
def heuristic(state):
    '''
    Guide the search by estimating remaining cost to goal state.
    Now for two players and calculates Zero-sum payoff
    '''
    #initialize empty list of coordinates of resources that need to still be delivered to base
    #remaining = []
    #initialize dict of how many resources are required for goal state from beginning
    required = {
        "Stone": 3,
        "Iron": 2,
        "Crystal": 1
        }
    
    #helper function for heuristic
    def score_player(pos, backpack, finished, player_turn):
        ''''
        Gets score of player
        '''
        #calculates resources still needed into a dict
        needed = {}
        for resource in required:
            needed[resource] = max(0, required[resource] - finished[resource])
        
        #initialize list of remaining coodinates
        coordinates_remaining = []
        #get remaining coordinates
        for resource, count in needed.items():
            if count > 0:
                coordinates_remaining.extend(state.resources.get(resource, []))

        #if backpack has resources, return to base
        if len(backpack) > 0:  #depending on player turn, base is different
            if player_turn == 'a':
                base = (0,0)
            else:
                base = (4,4)
            #if at base, slightly higher score
            if pos == base:
                return 0
            #strong incentive to head to base
            return -10000 * (abs(pos[0] - base[0]) + abs(pos[1] - base[1]))
        elif coordinates_remaining:
            #calculate distance to remaining resource that is closest
            distances = []
            for resource in coordinates_remaining:
                distance = abs(pos[0]-resource[0]) + abs(pos[1]-resource[1])
                distances.append(distance)
            if distances:
                return -min(distances)    
        else:
            return -0.1
    
    score_a = score_player(state.pos_a, state.backpack_a, state.finished["a"], 'a')
    score_b = score_player(state.pos_b, state.backpack_b, state.finished["b"], 'b')

    #zero sum calc to return
    diff_delivery = 0
    for resource in required:
        diff_delivery += state.finished["a"][resource] - state.finished["b"][resource]
    
    return diff_delivery + score_a - score_b
