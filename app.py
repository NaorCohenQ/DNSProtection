from flask import Flask, render_template, request, jsonify
from simulatorAttacker import Simulator  # Import the simulator from your code
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # Render the UI page

@app.route('/rhhh')
def rhhh_info():
    return render_template('rhhh.html')  # Render the RHHH information page

@app.route('/run_simulation', methods=['POST'])
def run_simulation():
    # Get parameters from the form
    attack_perc = int(request.form['attack_perc'])

    # Initialize and run the simulator
    simulator = Simulator()
    simulator.simulate_attack(attack_perc, -1)  # Call your existing simulator

    # Collect statistics from the simulation
    blocked_count = simulator.blocked_stats()
    total_requests = simulator.total_req_stats()
    legit_blocked = simulator.legit_block_stats()

    # Prepare the results to send back to the frontend
    results = {
        'blocked_count': blocked_count,
        'total_requests': total_requests,
        'legit_blocked': legit_blocked
    }

    return jsonify(results)  # Return the results as JSON to the frontend

if __name__ == '__main__':
    app.run(debug=True)
