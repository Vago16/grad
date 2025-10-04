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
    
    ##Player a##
    #initialize empty dict of how many resources are still needed for the goal state for player a
    needed_a = {}
    #loop to iterate and fill in needed    
    for resource in required:
        difference = required[resource] - state.finished["a"][resource]    #get the difference between what has been taken to base and still needs to be taken to base
        if difference > 0:
            needed_a[resource] = difference
        else:
            needed_a[resource] = 0        #prevents negative values of resources
    
    #initliaze empty list for remaining resources to collect
    remaining_a = []
    #check to see if/how many resources are on the map and record them
    for resource in needed_a:
        if needed_a[resource] > 0:  #if there are still resources on the map to be collected, record position of them
            for coordinate in state.resources[resource]:
                remaining_a.append(coordinate)


    #if backpack is full, utilize Manhattan Distance to get back to base (https://theory.stanford.edu/~amitp/GameProgramming/Heuristics.html)
    #and zero sum calculations(https://www.geeksforgeeks.org/artificial-intelligence/adversarial-search-algorithms/)
    if len(state.backpack_a) == 2:
        #return abs(state.pos[0]) + abs(state.pos[1])    #manahattan distance with absolute values to make sure its computed correctly
        score_a = -(abs(state.pos_a[0] - 0) + abs(state.pos_a[1] - 0))
    elif remaining_a:
        min_distance = None
        for coordinate in remaining_a:
            distance = abs(state.pos_a[0] - coordinate[0]) + abs(state.pos_a[1] - coordinate[1])
            if min_distance is None or distance < min_distance:
                min_distance = distance
        score_a = -min_distance
    else:
        score_a = 0
    
    ##player b##
    #initialize empty dict of how many resources are still needed for the goal state for player b
    needed_b = {}
    #loop to iterate and fill in needed    
    for resource in required:
        difference = required[resource] - state.finished["b"][resource]    #get the difference between what has been taken to base and still needs to be taken to base
        if difference > 0:
            needed_b[resource] = difference
        else:
            needed_b[resource] = 0        #prevents negative values of resources
    
    #initliaze empty list for remaining resources to collect
    remaining_b = []
    #check to see if/how many resources are on the map and record them
    for resource in needed_b:
        if needed_b[resource] > 0:  #if there are still resources on the map to be collected, record position of them
            for coordinate in state.resources[resource]:
                remaining_b.append(coordinate)


    #if backpack is full, utilize Manhattan Distance to get back to base (https://theory.stanford.edu/~amitp/GameProgramming/Heuristics.html)
    #and zero sum calculations(https://www.geeksforgeeks.org/artificial-intelligence/adversarial-search-algorithms/)
    if len(state.backpack_b) == 2:
        #return abs(state.pos[0]) + abs(state.pos[1])    #manahattan distance with absolute values to make sure its computed correctly
        score_b = -(abs(state.pos_b[0] - 4) + abs(state.pos_b[1] - 4))
    elif remaining_b:
        min_distance = None
        for coordinate in remaining_b:
            distance = abs(state.pos_b[0] - coordinate[0]) + abs(state.pos_b[1] - coordinate[1])
            if min_distance is None or distance < min_distance:
                min_distance = distance
        score_b = -min_distance
    else:
        score_b = 0

    #checking to see the difference in delivered resources
    diff_delivery = 0

    for resource in required:
        diff_delivery += state.finished["a"][resource] - state.finished["b"][resource]
    #zero sum calc to return
    return diff_delivery + score_a - score_b
