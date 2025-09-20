#represents state of the map

#define class for state of the map
class State:
    def __init__(self, pos, backpack, finished):
        '''
        pos- position on the map in row and column of the agent
        backpack- tuple representing leather backpack that can only hold up to two resources at a time at most
        finished- a dict with the resources that have been taken successfully to the base(0,0) coordinate
        '''
        self.pos = pos
        self.backpack = tuple(backpack)
        self.finished = dict(finished) 