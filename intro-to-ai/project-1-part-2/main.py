import maps
import state
import heuristic
import heapq        #for priority queue data structure
# main file that contains the A* seach algorithm

########helper functions for A*#######

#function that returns True when the base has enough of each resource needed
def goal_reached(state):
    #initialize dict of how many resources are required for goal state from beginning
    required = {
        "Stone": 3,
        "Iron": 2,
        "Crystal": 1
        }
    #if not enough of any resource, return False, otherwise, function returns True
    for resource, num in required.items():
        if state.finished[resource] < num:
            return False
    return True

#function to reconstruct path


######A* Search Algorithm#######

#implementation of A*, idea for heapq help came from https://www.datacamp.com/tutorial/a-star-algorithm
def astar(initial_state, given_map, terrain_costs):
    '''
    initial_state: the State object representing base and start of the search((0,0), 
        no resources in bag, and all resources on map still)
    given_map, terrain_costs: args for get_neighbor function from state.py
    '''
    #initialize empty list for the priority queue to be the frontier(the open list)
    open_list = []
    heapq.heappush(open_list, heuristic(initial_state), 0, initial_state, None)

    #initialize empty set for closed list(states already visited)
    closed_set = set()
    #initialize empty dict for parent states
    parents = {}

    #main loop - go through open list 
    while open_list:
        #f = g + h, the total path cost, where g is the cost so far and h is heuristic estimation
        f, g, curr, parent = heapq.heappop(open_list)

        #skip if duplicate state(already seen)
        if curr in closed_set:
            continue

        #save parent pointer off the popped current(curr variable)
        parents[curr] = parent

        #check if goal has been met, and if so, call function to reconstruct path used
        if goal_reached(curr):
            pass

    #if went through whole search with no goal
    return None