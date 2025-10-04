import state
import heuristic

######Minimax Search Algorithm#######
#https://www.geeksforgeeks.org/artificial-intelligence/adversarial-search-algorithms/
def minimax(state_obj, depth, alpha, beta, maximizing_player, given_map, terrain_costs):
    '''
    Depth limited minimax search algorithm with alpha beta pruning.
    state_obj: state of the game
    depth: how many ahead the algorithm checks
    alpha: the best value maximizng player can get
    beta: the best value minimizing player can get 
    maximizing_player: True if player a (the player whose score we are maximizing)
    given_map, terrain_costs: passed for get_neighbor function to work
    '''
    #if no more moves to make or goal has been reached
    if depth == 0 or state.check_goal(state_obj):    
        return heuristic.heuristic(state_obj), state_obj    #returns heuristic of state
    
    #get all possible moves for current player
    neighbors = []  #empty list initialization
    for neighbor, _ in state.get_neighbor(state_obj, given_map, terrain_costs):  #_ igrnores second element(cost)
        neighbors.append(neighbor)

    #if it is the turn of player we want to maximize score of
    if maximizing_player:
        max = float('-inf') #starts as negative infinity, want a positive number to finish with
        max_state = None    #state that will have the max score

        #iterate throguh each neighbor and recursively call minimax to explore states
        for child in neighbors:
            evaluate_score, _ = minimax(child, depth-1, alpha, beta, False, given_map, terrain_costs)   #False refers to maximizing player, as it will be minimzing player's turn next
            
            if evaluate_score > max:
                max = evaluate_score    #max score becomes equal to the new score if higher than it
                max_state = child   #the state where the new max score has been achieved is recorded
            
            alpha = max(alpha, evaluate_score)  #update alpha
            #alpha-beta pruning, since minimizing player will not allow it
            if beta <= alpha:
                break
        
        return max, max_state
    else:   #if minimizing player
        min = float('inf') #starts as positive infinity, want a negative number to finish with
        min_state = None    #state that will have the min score

        #iterate throguh each neighbor and recursively call minimax to explore states
        for child in neighbors:
            evaluate_score, _ = minimax(child, depth-1, alpha, beta, True, given_map, terrain_costs)   #False refers to maximizing player, as it will be minimzing player's turn next
            
            if evaluate_score < min:
                min = evaluate_score    #min score becomes equal to the new score if lower than it
                min_state = child   #the state where the new in score has been achieved is recorded
            
            beta = min(beta, evaluate_score)  #update beta
            #alpha-beta pruning, since minimizing player will not allow it
            if beta <= alpha:
                break

        return min, min_state
    
def get_move():
    '''
    Function to get the best next move and returns the state for it for current player
    '''
    pass