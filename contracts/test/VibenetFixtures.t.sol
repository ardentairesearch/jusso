// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Counter } from "../src/test/Counter.sol";

contract VibenetFixturesTest {
    function testCounterProvidesAVisibleNativeAaTarget() external {
        Counter counter = new Counter();
        require(counter.number() == 0, "unexpected initial number");

        counter.increment();
        require(counter.number() == 1, "increment failed");
    }
}
