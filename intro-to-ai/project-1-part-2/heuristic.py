import state
#Heuristic for the search algorithm

#admissible heuristic function, used https://www.geeksforgeeks.org/artificial-intelligence/heuristic-function-in-ai/ for help in understanding further
def heuristic(state):
    '''
    Guide the search by estimating remaining cost to goal state
    Minimum Manhattan distance to nearest needed resource.
    Distance to base if backpack is full.
    '''
    #initialize empty list of coordinates of resources that need to still be delivered to base
    remaining = []
    #initialize dict of how many resources are required for goal state from beginning
    required = {
        "Stone": 3,
        "Iron": 2,
        "Crystal": 1
        }
    #initialize empty dict of how many resources are still needed for the goal state
    needed = {}
    #loop to iterate and fill in needed    
    for resource, required in required.items():
        difference = required - state.finished[resource]    #get the difference between what has been taken to base and still needs to be taken to base
        if difference > 0:
            needed[resource] = difference
        else:
            needed[resource] = 0        #prevents negative values of resources

    #if there is still any resources remaining, put into remaining list so heuristic knows to get them
    for resource, num in needed.items():
        if num > 0:     #if there is still a number of resource remaining, add to list with coordinates of them
            remaining.extend(state.resources[resource])

    #if backpack is full, utilize Manhattan Distance to get back to base (https://theory.stanford.edu/~amitp/GameProgramming/Heuristics.html)
    if len(state.backpack) == 2:
        return abs(state.pos[0]) + abs(state.pos[1])    #manahattan distance with absolute values to make sure its computed correctly
    
    #if no more resources need to be delivered, means we are done
    if not remaining:
        return 0
    
    #initialize a list that stores distances to each resource needed
    distances = []
    for resource in remaining:
        #manahattan distance with absolute values to make sure its computed correctly
        dist= abs(state.pos[0] - resource[0]) + abs(state.pos[1] - resource[1])
        distances.append(dist)
    #return the smallest distance to closest remaining resource
    if not distances:   #make sure distances list is not empty to prevent min() function from crashing/acting unexpectedly
        return 0
    return min(distances)

