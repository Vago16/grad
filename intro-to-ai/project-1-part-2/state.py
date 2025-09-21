import maps

#represents state(node) of the map

#define class for state of the map, each object of state class represents a node in search
class State:
    def __init__(self, pos, backpack, finished):
        '''
        pos- tuple showing position on the map in row and column of the agent
        backpack- tuple representing leather backpack that can only hold up to two resources at a time at most
        finished- a dict with the resources that have been taken successfully to the base(0,0) coordinate
        '''
        self.pos = pos
        self.backpack = tuple(backpack)
        self.finished = dict(finished) 
    
    def __eq__(self, other):        #checks state against another specified state to see if they are equal(position, contents of backpack, and however many resources have been taken to base)
        return(
            self.pos == other.pos and
            self.backpack == other.backpack and
            self.finished == other.finished
        )
    
    def __hash__(self):     #hash the state(making tuple out of self.finished lets it be hashable)
        return hash((self.pos, self.backpack, tuple(self.finished.items())))

    def __repr__(self):     #print out state
        return f"Position: {self.pos}, Contents in Backpack: {self.backpack}, Resources delivered: {self.finished}"

#move function to move the agent to adjacent tiles
def move_agent():
    '''
    Move the agent to a new position on the map and pick up/drop off resources
    '''
    pass

#get_neighbor function
#I got some help from https://stackoverflow.com/questions/77274736/how-to-find-neighbors-in-a-grid for figuring it out
def get_neighbor(state, map, resource_list, terrain_costs):
    '''
    Return a list of all adjacent(neighbor) states from current state 
    and their movement costs.
    '''
    neighbors = []     #list to be appended and returned at end of function
    rows, columns = len(map), len(map[0])   #gets the dimensions of the map
    curr_row, curr_col = state.pos

    directions = [(-1,0), (1,0), (0,-1), (0,1)] #all the possible directions that can be moved to in a 2-D array

    for dir_row, dir_col in directions:   #for each direction
        neighor_row, neighbor_col = curr_row + dir_row, curr_col + dir_col




#####TESTS#####
#testing to see if state class and functions work
state1 = State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0}
)

state2 = State(
    pos=(0, 0),
    backpack=(),
    finished={"Stone": 0, "Iron": 0, "Crystal": 0}
)

state3 = State(
    pos=(0, 3),
    backpack=(),
    finished={"Stone": 0, "Iron": 1, "Crystal": 0}
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