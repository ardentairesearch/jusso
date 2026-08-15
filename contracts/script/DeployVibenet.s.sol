// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Counter } from "../src/test/Counter.sol";

interface Vm {
    function envUint(string calldata name) external view returns (uint256);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeployVibenet {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event VibenetFixtureDeployed(address indexed counter);

    function run() external returns (Counter counter) {
        uint256 deployerKey = VM.envUint("PRIVATE_KEY");

        VM.startBroadcast(deployerKey);
        counter = new Counter();
        VM.stopBroadcast();

        emit VibenetFixtureDeployed(address(counter));
    }
}
