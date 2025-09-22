import maps
import state
import heuristic
import heapq        #for priority queue data structure
# main file that contains the A* seach algorithm

########helper functions for A*#######

def goal_reached(state):
    '''
    Function that returns True when the base has enough of each resource needed
    '''
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

def make_path(state, parents):
    '''
    Uses parent nodes to reconstruct path
    '''
    #initialize empty list for path to tackle
    path = []
    while state is not None:    #while there is a state, add the state to the path list, then go to the parent node
        path.append(state)
        state = parents[state]
    path.reverse()  #reverse order so its order is from start to end instead of end to start

    return path

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
    #heapq.heappush method takes two args
    heapq.heappush(open_list, (heuristic.heuristic(initial_state), 0, initial_state, None))

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

        #check if goal has been met, and if so, call function to reconstruct path used from start state to goal state
        if goal_reached(curr):
            return make_path(curr, parents)
        
        #after current node has been explored, add to closed list so it wont be expanded into(not in frontier anymore)
        closed_set.add(curr)

        #iterate through calling of get_neighbor function to check all adjacent tiles and get heuristic
        for neighbor, cost in state.get_neighbor(curr, given_map, terrain_costs):
            if neighbor in closed_set:      #neighbor has already been expanded into, so it can be skipped
                continue
            #once again dealing with f = g + h, the total path cost(priority value), where g is the cost so far and h is heuristic estimation  
            n_g = g + cost
            n_f = n_g + heuristic.heuristic(neighbor) #gets heuristic estimation of neighbor
            #push to priority queue, current node becomes the parent for neighbor as curr variable is passed to parent pointer arg
            heapq.heappush(open_list, (n_f, n_g, neighbor, curr))

    #if search went through whole search with no goal
    return None
