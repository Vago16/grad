import maps

#represents state(node) of the map

#define class for state of the map, each object of state class represents a node in search
class State:
    def __init__(self, pos, backpack, finished, resources):
        '''
        pos- tuple showing position on the map in row and column of the agent
        backpack- tuple representing leather backpack that can only hold up to two resources at a time at most
        finished- a dict with the resources that have been taken successfully to the base(0,0) coordinate
        resources- a dictionary with a list of copies of each resource
        '''
        self.pos = pos
        self.backpack = tuple(backpack)
        self.finished = dict(finished) 

        self.resources = {}
        for resource, coordinates in resources.items(): #iterate through each of the items(resources) and go through each tile on the map
            self.resources[resource] = list(coordinates)
    
    def __eq__(self, other):        #checks state against another specified state to see if they are equal(position, contents of backpack, and however many resources have been taken to base)
        return(
            self.pos == other.pos and
            self.backpack == other.backpack and
            self.finished == other.finished and
            self.resources == other.resources
        )
    
    def __hash__(self):     #hash the state(making tuple out of self.finished lets it be hashable)
        resource_items = []
        for resource, coordinates in self.resources.items(): #iterate through each of the items(resources) and go through each tile on the map
            resource_items.append((resource, tuple(coordinates)))       #convert each list to tuples before appending to allow hashing
        resources_tupled = tuple(resource_items)        #convert overall list to tuple

        return hash((self.pos, self.backpack, tuple(self.finished.items()), resources_tupled))

    def __repr__(self):     #print out state
        return f"Position: {self.pos}, Contents in Backpack: {self.backpack}, Resources delivered: {self.finished}, Resources left: {self.resources}"

#move function to handle moving the agent to adjacent tiles
def move_agent(state, new_pos, given_map, terrain_costs):
    '''
    Move the agent to a new position on the map and pick up/drop off resources
    '''
    #copy backpack and its contents(if any) to a list, and copy delivered resources to a dict
    new_pack = list(state.backpack) 
    new_finished = dict(state.finished)
    #make a dict copy of resouces that will not modify original state
    new_resources = {}
    for resource, coordinates in state.resources.items(): #iterate through each of the items(resources) and go through each tile on the map
        new_resources[resource] = list(coordinates)

    #if the tile has resource and backpack has space, pick up resource
    for resource, coordinate in new_resources.items(): #iterate through coordinates and resource items in the list
        if new_pos in coordinate and len(new_pack) < 2:     #if there is room in the backpack(less than 2 items currently)
            new_pack.append(resource)
            coordinate.remove(new_pos) #remove resource from map

    #if the tile is the base tile
    if new_pos == (0,0) and new_pack:   #(0,0) is always base and makes sure there is a new_pack variable that is True
        for resource in new_pack:
            new_finished[resource] += 1     #add resources to count 
        new_pack = []       #empty backpack completely

    #return new state(node)
    return State(
        pos=new_pos,
        backpack=new_pack,
        finished=new_finished,
        resources=new_resources
    )

#get_neighbor function
#I got some help from https://stackoverflow.com/questions/77274736/how-to-find-neighbors-in-a-grid for figuring it out
def get_neighbor(state, given_map, terrain_costs):
    '''
    Return a list of all adjacent(neighbor) states from current state 
    and their movement costs.
    '''
    neighbors = []     #list to be appended and returned at end of function
    rows, columns = len(given_map), len(given_map[0])   #gets the dimensions of the map
    curr_row, curr_col = state.pos

    directions = [(-1,0), (1,0), (0,-1), (0,1)] #all the possible directions that can be moved to in a 2-D array

    for dir_row, dir_col in directions:   #for each direction
        neighbor_row = curr_row + dir_row   #get neighbor coordinates
        neighbor_col = curr_col + dir_col  

        if 0 <= neighbor_row < rows and 0 <= neighbor_col < columns:    #makes sure that the agent cannot move off the map in error
            new_pos = (neighbor_row, neighbor_col)  #stores neighboring states positions
            neighbor_state = move_agent(state, new_pos, given_map, terrain_costs)     #call move_agent function to move agent

            #get the cost for moved onto tile/terrain
            terrain = given_map[neighbor_row][neighbor_col]
            movement_cost = terrain_costs[terrain] + 1  #get the movement cost for the specific terrain(and add 1 as it always costs 1 to move)

            #append to list for the state and movement cost
            neighbors.append((neighbor_state, movement_cost))

    return neighbors

#function to see if the goal has been met(3 stones, 2 irons, and 1 crystal delivered to base)
def check_goal(state):
    return (
        state.finished["Stone"] >= 3 and
        state.finished["Iron"] >= 2 and
        state.finished["Crystal"] >= 1
    )

#####TESTS#####
#testing to see if state class and functions work
state1 = State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_3
)

state2 = State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0},
    resources=maps.resource_list_3
)

state3 = State(
    pos=(0, 3),
    backpack=(),
    finished={"Stone": 0, "Iron": 1, "Crystal": 0},
    resources=maps.resource_list_3
)

#testing equality
print(state1 == state2)
print(state1 == state3)

#testing hash
visited1 = set()
visited1.add(state1)
visited1.add(state2)
print(len(visited1))

visited2 = set()
visited2.add(state1)
visited2.add(state3)
print(len(visited2))

#testing print
print(state1)
print(state2)
print(state3)
print() #newline for readability

#Testing get_neighbor function
neighbors = get_neighbor(state1, maps.map_3, maps.terrain_costs)

for neighbor, cost in neighbors:
    print(f"Move to {neighbor.pos} with cost {cost}")
    print(f"  Backpack: {neighbor.backpack}, Delivered: {neighbor.finished}")
    print()