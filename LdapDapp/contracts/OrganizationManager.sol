// SPDX-License-Identifier: MIT
pragma solidity >=0.4.25 <0.9.0;
import "./AccessManager.sol";
pragma experimental ABIEncoderV2;
contract OrganizationManager {
    constructor() public {
         for (uint i = 0; i < _orgsArr.length; i++) {
             _orgs[_orgsArr[i]] = true;
         }
    }
    
    fallback() external {
        // fallback function
    }
    
    struct UserInfo {
        address lastModifyOrg;          // [org2.id]
        address accessManagerAddress;   // address of access control manager
        address userAddress;            // binding addrss
        mapping(address => bool) orgs;  // [org1.id, org2.id]
    }
    
    // Pre-registered organization
    address[] _orgsArr = [  0x88F49872957691A64D6E3f73c271f35Ade9B0805, 
                            0xfEA00332F1224F03ceEd15a277A9297492bf5954,
                            0x006a1566c1A3D6fBf99514683675001C2FA9cb5f,
                            0xfA1062E880e512090e08d8DbDDbb72A523b0bf7d,
                            0xD1F8f56aE42A23c9Ad3D6D903eBB2dD14698cFD0];
    
    // Pre-registered attributes
    string[] _attributes = ["deposit", "pii", "aaa"];
    string[] _oneApprovedAttrs = ["bill", "bbb", "ggg"];

    // Permission of user and organization
    mapping (address => bool) _orgs;
    mapping(address => bool) _users;
    
    //     
    mapping(address => bytes32) _bindUsers;
    mapping(bytes32 => bool) _uniqueState;
    mapping(bytes32 => bool) _bindState;
    mapping(bytes32 => UserInfo) _uniqueIdenity;
    
    // Events
    event AddUserEvent(address orgAddress, uint status);
    event BindUserAccountEvent(address orgAddress, address userAccount, bytes32 hashed);
    event ReBindUserAccountEvent(address orgAddress, address oldAccount, address userAccount, bytes32 hashed);

    uint256 _state;
    
    modifier onlyOrg {
        require(_orgs[msg.sender],
                "Only organization administrator can call.");
        _;
    }

    modifier onlyUser {
        require(_users[msg.sender],
                "Only registered user can call.");
        _;
    }
    
    function addUser(
        string memory uniqueId
    )
        public onlyOrg
    {
        bytes32 hashed = keccak256(bytes(uniqueId));
        if (_uniqueState[hashed]) {
            // alreay exist and add org
            _uniqueIdenity[hashed].orgs[msg.sender] = true;
            _uniqueIdenity[hashed].lastModifyOrg = msg.sender;
            emit AddUserEvent(msg.sender, 0);
        }
        else {
            _uniqueState[hashed] = true;
            UserInfo storage info = _uniqueIdenity[hashed];

            info.lastModifyOrg = msg.sender;
            info.accessManagerAddress = address(0);
            info.userAddress = address(0);                          
                                    
            info.orgs[msg.sender] = true;
            emit AddUserEvent(msg.sender, 1);
        }
    }

    // bind user identity(hash of ID card number) with ethereum account
    function bindAccount(
        string memory uniqueId,
        address userAddress
    )
        public onlyOrg
    {
        require(_bindUsers[userAddress] == 0,
                "This address already binded.");
        require(_bindState[keccak256(bytes(uniqueId))] == false,
                "This UniqueId already binded");
        require(_uniqueState[keccak256(bytes(uniqueId))],
                "UniqueId invalid.");
        bytes32 hashed = keccak256(bytes(uniqueId));

        _bindUsers[userAddress] = hashed;    // for record address <==> hashed id
        _bindState[hashed] = true;           // for confirm this hashed id already bind before
        _users[userAddress] = true;          // for modifier onlyUser

        // create contract and transfer ownership to user himself
        AccessManager accessManager = new AccessManager();
        accessManager.transferOwnership(userAddress);
        
        // update user info
        _uniqueIdenity[hashed].accessManagerAddress = address(accessManager);
        _uniqueIdenity[hashed].userAddress = userAddress;
        
        emit BindUserAccountEvent(msg.sender, userAddress, hashed);
    }

    function rebindAccount(
        string memory uniqueId,
        address newAddress
    )
        public onlyOrg
    {
        require(_bindUsers[newAddress] == 0,
                "This address already binded.");
        require(_bindState[keccak256(bytes(uniqueId))] == true,
                "This UniqueId does not yet bind.");
        require(_uniqueState[keccak256(bytes(uniqueId))],
                "UniqueId invalid.");
        bytes32 hashed = keccak256(bytes(uniqueId));
        
        // unbind old one
        address oldAddress = _uniqueIdenity[hashed].userAddress;
        _bindUsers[oldAddress] = 0;
        _users[oldAddress] = false;
        
        //bind new one
        _bindUsers[newAddress] = hashed; 
        _users[newAddress] = true;
        
        // create contract and transfer ownership to user himself
        AccessManager accessManager = new AccessManager();
        accessManager.transferOwnership(newAddress);
        
        // update user info
        _uniqueIdenity[hashed].accessManagerAddress = address(accessManager);
        _uniqueIdenity[hashed].userAddress = newAddress;
        
        emit ReBindUserAccountEvent(msg.sender, oldAddress, newAddress, hashed);        
    }

    function checkLastModify(string memory uniqueId) public view returns (address){
        return (_uniqueIdenity[keccak256(bytes(uniqueId))]).lastModifyOrg;
    }
        
    function checkOrgs(string memory uniqueId) public view returns (bool) {
        return _uniqueIdenity[keccak256(bytes(uniqueId))].orgs[msg.sender];
    }
    
    function isRegistered(address orgAddress) public view returns (bool) {
        require(_bindUsers[msg.sender] != 0,
                "Binding before account opening.");
        return _uniqueIdenity[_bindUsers[msg.sender]].orgs[orgAddress];
    }
    
    function getIdentity(string memory userId) public view returns (string memory) {
        // if (keccak256(bytes(_userOrgMap[userId])) == keccak256(bytes(""))) return "Not found";
        // return _userOrgMap[userId];
    }
    
    function getOrg(uint idx) public onlyOrg view returns (address) {
        if (idx >= _orgsArr.length) return address(0);
        return _orgsArr[idx];
    }
    
    // Get hashed id by plaintext id number
    function getId(string memory uniqueId) public onlyOrg view returns (bytes32) {
        bytes32 hashed = keccak256(bytes(uniqueId));
        if (_uniqueState[hashed]) return hashed;
        return 0;
    }
    
    // Get hashed id by etherenum address(msg.sender)
    function getId() public view returns (bytes32) {
        return _bindUsers[msg.sender];
    }

    // Get address by unique id
    function getAddress(string memory uniqueId) public onlyOrg view returns (address) {
        bytes32 hashed = keccak256(bytes(uniqueId));
        return _uniqueIdenity[hashed].userAddress;
    }

    // Get address by unique id
    function getAddressByHashed(bytes32 hashed) public onlyOrg view returns (address) {
        return _uniqueIdenity[hashed].userAddress;
    }

    // Get hashed id by orgs
    function getIdByOrg(address userAddress) public onlyOrg view returns (bytes32) {
        return _bindUsers[userAddress];
    } 

    // Get Org list by anyone
    function getOrgList() public view returns (address [] memory) {
        return _orgsArr;
    }

    // Get Org list by anyone
    function getAttrList() public view returns (string [] memory) {
        return _attributes;
    }

    // Get Org list by anyone
    function getOneApprovedAttrsList() public view returns (string [] memory) {
        return _oneApprovedAttrs;
    }

    // Get Contract address by UserManager
    function getAccessManagerAddress(address userAddress) public view returns (address) {
        return _uniqueIdenity[_bindUsers[userAddress]].accessManagerAddress;
    }
}


// contract UserManager {
//     // TODO
// }


// contract LogManager {
//     // TODO
// }


// contract AccessManager {
//     // TODO
// }