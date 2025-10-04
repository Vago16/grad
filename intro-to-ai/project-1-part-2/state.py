import maps

#represents state(node) of the map

#define class for state of the map, each object of state class represents a node in search
#now include two players, a and b, in position and backpack, and turns
class State:
    def __init__(self, pos_a, pos_b, backpack_a, backpack_b, finished, resources, turn):
        '''
        pos- tuple showing position on the map in row and column of the agent
        backpack- tuple representing leather backpack that can only hold up to two resources at a time at most
        finished- a dict with the resources that have been taken successfully to the base(0,0) coordinate
        resources- a dictionary with a list of copies of each resource
        '''
        self.pos_a = pos_a
        self.pos_b = pos_b
        self.backpack_a = tuple(backpack_a)
        self.backpack_b = tuple(backpack_b)
        #seperate dicts depending on player
        self.finished = {
            "a": dict(finished.get("a", {"stone":0, "iron":0, "crystal":0})),
            "b": dict(finished.get("b", {"stone":0, "iron":0, "crystal":0})),
        }

        self.resources = {}
        for resource, coordinates in resources.items(): #iterate through each of the items(resources) and go through each tile on the map
            self.resources[resource] = list(coordinates)

        self.turn = turn
    
    def __eq__(self, other):        #checks state against another specified state to see if they are equal(position, contents of backpack, and however many resources have been taken to base)
        return(
            self.pos_a == other.pos_a and
            self.pos_b == other.pos_b and
            self.backpack_a == other.backpack_a and
            self.backpack_b == other.backpack_b and
            self.finished == other.finished and
            self.resources == other.resources and
            self.turn == other.turn
        )
    
    def __hash__(self):     #hash the state(making tuple out of self.finished lets it be hashable)
        resource_items = []
        for resource, coordinates in self.resources.items(): #iterate through each of the items(resources) and go through each tile on the map
            resource_items.append((resource, tuple(coordinates)))       #convert each list to tuples before appending to allow hashing
        resources_tupled = tuple(resource_items)        #convert overall list to tuple

        #converts finished into tuple so it can be hashed
        finished_tuple = (tuple(self.finished["a"].items()),
                          tuple(self.finished["b"].items()))
        
        return hash((self.pos_a, self.backpack_a, 
                     self.pos_b, self.backpack_b,
                     finished_tuple, resources_tupled, self.turn))

    def __repr__(self):     #print out state for both players
        return (f"Player 1 Status - Position: {self.pos_a}, Contents in Backpack: {self.backpack_a}.  " 
                f"Player 2 Status - Position: {self.pos_b}, Contents in Backpack: {self.backpack_b}.  " 
                f"Resources delivered: {self.finished}.  Resources left: {self.resources}.  "
                f"Turn: {self.turn}")

#move function to handle moving the agent to adjacent tiles
def move_agent(state, new_pos, given_map, terrain_costs):
    '''
    Move the agent(a or b) to a new position on the map and pick up/drop off resources
    '''
    #copy delivered resources to a dict for both players
    new_finished = {
    "a": dict(state.finished["a"]),
    "b": dict(state.finished["b"])
}
    #make a dict copy of resouces that will not modify original state
    new_resources = {}
    for resource, coordinates in state.resources.items(): #iterate through each of the items(resources) and go through each tile on the map
        new_resources[resource] = list(coordinates)

    #check player's turn 
    if state.turn =="a":
        #curr_pos = state.pos_a
        new_pack = list(state.backpack_a)
        base = (0,0)    #player a's base
    else:
        #curr_pos = state.pos_b
        new_pack = list(state.backpack_b)
        base = (4,4)    #player b's base

    #if the tile has resource and backpack has space, pick up resource
    for resource, coordinate in new_resources.items(): #iterate through coordinates and resource items in the list
        if new_pos in coordinate and len(new_pack) < 2:     #if there is room in the backpack(less than 2 items currently)
            new_pack.append(resource)
            coordinate.remove(new_pos) #remove resource from map

    #if the tile is the base tile
    if new_pos == base and new_pack:   #(0,0) is always base and makes sure there is a new_pack variable that is True
        for resource in new_pack:
            new_finished[state.turn][resource] += 1     #add resources to count for current player
        new_pack = []       #empty backpack completely of current player

    #return new state(node) of players depending on turn
    if state.turn == 'a':
        new_state = State(
        pos_a=new_pos,
        pos_b=state.pos_b,  #record other player's postion
        backpack_a=new_pack,
        backpack_b=state.backpack_b,
        finished=new_finished,
        resources=new_resources,
        turn="b"    #switch turn
    )
    else:
        new_state = State(
        pos_a=state.pos_a,  #record other player's postion
        pos_b=new_pos, 
        backpack_a=state.backpack_a,
        backpack_b=new_pack,
        finished=new_finished,
        resources=new_resources,
        turn="a"    #switch turn
    )
    return new_state

#get_neighbor function
#I got some help from https://stackoverflow.com/questions/77274736/how-to-find-neighbors-in-a-grid for figuring it out
def get_neighbor(state, given_map, terrain_costs):
    '''
    Return a list of all adjacent(neighbor) states from current state 
    and their movement costs.
    '''
    neighbors = []     #list to be appended and returned at end of function
    rows, columns = len(given_map), len(given_map[0])   #gets the dimensions of the map

    #checks for player's turn
    if state.turn == "a":
        curr_row, curr_col = state.pos_a
    else:
        curr_row, curr_col = state.pos_b

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
##now checks to see if resources have been depleted as either player is unlikely to have all the resources
def check_goal(state):
    #have all resources been picked up?
    for coordinates in state.resources.values():
        if len(coordinates) > 0:    #at least one resource is still on the map
            return False
    
    #does any players' backpacks still have items inside?
    if state.backpack_a or state.backpack_b:    #backpacks need to be emptied at corresponding base
        return False

    return True
