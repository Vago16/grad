#represents state of the map

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