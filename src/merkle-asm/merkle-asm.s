# Incremental Merkle Tree

.equ ACCOUNT_BASE_SIZE, 10336 

.equ ST_AUTHORITY,       0x00
.equ ST_DEPTH,           0x20
.equ ST_BUMP,            0x21
.equ ST_NEXT_INDEX,      0x24
.equ ST_CURRENT_ROOT,    0x28
.equ ST_FILLED_SUBTREES, 0x48

.equ DEPTH,     20
.equ HASH_SIZE, 32

.globl entrypoint

entrypoint:
    # 1. Validation
    ldxdw r0, [r1+0]
    jge r0, 2, val_ok
    mov64 r0, 1 # ERR_NOT_ENOUGH_ACCOUNTS
    exit
val_ok:

    # 2. Extract Instruction Pointer
    call parse_input

    # 3. Router
    ldxb r0, [r2+0]
    jeq r0, 0, ix_initialize
    jeq r0, 1, ix_insert
    jeq r0, 2, ix_verify
    mov64 r0, 4 # ERR_INVALID_IX_DATA
    exit


# DYNAMIC BUFFER PARSERS

get_account_data_ptr:
    mov64 r3, r1
    add64 r3, 8
gadp_loop:
    jeq r2, 0, gadp_found
    ldxb r5, [r3+0]
    jne r5, 255, gadp_skip
    ldxdw r6, [r3+80]
    add64 r3, ACCOUNT_BASE_SIZE
    add64 r3, r6                  
    add64 r3, 7
    and64 r3, -8
    sub64 r2, 1
    ja gadp_loop
gadp_skip:
    add64 r3, 8
    sub64 r2, 1
    ja gadp_loop
gadp_found:
    add64 r3, 88
    mov64 r0, r3
    exit

get_account_key_ptr:
    mov64 r3, r1
    add64 r3, 8
gakp_loop:
    jeq r2, 0, gakp_found
    ldxb r5, [r3+0]
    jne r5, 255, gakp_skip
    ldxdw r6, [r3+80]
    add64 r3, ACCOUNT_BASE_SIZE
    add64 r3, r6
    add64 r3, 7
    and64 r3, -8
    sub64 r2, 1
    ja gakp_loop
gakp_skip:
    add64 r3, 8
    sub64 r2, 1
    ja gakp_loop
gakp_found:
    add64 r3, 8
    mov64 r0, r3
    exit

parse_input:
    mov64 r3, r1
    ldxdw r5, [r3+0]              
    add64 r3, 8
    jeq r5, 0, pi_done
pi_loop:
    ldxb r6, [r3+0]
    jne r6, 255, pi_skip
    ldxdw r8, [r3+80]
    add64 r3, ACCOUNT_BASE_SIZE
    add64 r3, r8
    add64 r3, 7
    and64 r3, -8
    sub64 r5, 1
    jne r5, 0, pi_loop
    ja pi_done
pi_skip:
    add64 r3, 8
    sub64 r5, 1
    jne r5, 0, pi_loop
pi_done:
    add64 r3, 8
    mov64 r2, r3
    exit


# IX: INITIALIZE

ix_initialize:
    mov64 r9, r2                  
    stxdw [r10-72], r1            

    mov64 r2, 1                   
    call get_account_data_ptr
    mov64 r8, r0                  

    ldxb r0, [r8+ST_DEPTH]
    jeq r0, 0, init_depth_ok
    mov64 r0, 3 # ERR_ALREADY_INITIALIZED
    exit
init_depth_ok:

    mov64 r2, 0
    ldxdw r1, [r10-72]            
    call get_account_key_ptr
    mov64 r4, r0                  
    mov64 r1, r8                  
    mov64 r2, r4                  
    mov64 r3, 32
    call sol_memcpy_

    mov64 r0, DEPTH
    stxb [r8+ST_DEPTH], r0
    ldxb r0, [r9+1]               
    stxb [r8+ST_BUMP], r0
    mov64 r0, 0
    stxw [r8+ST_NEXT_INDEX], r0

    mov64 r1, 20
    mov64 r2, r8
    add64 r2, ST_CURRENT_ROOT
    call load_zero_hash

    mov64 r7, 0                   
init_loop:
    jeq r7, DEPTH, done_init
    mov64 r1, r7
    mov64 r2, r8
    add64 r2, ST_FILLED_SUBTREES
    mov64 r0, r7
    mul64 r0, HASH_SIZE
    add64 r2, r0
    call load_zero_hash
    add64 r7, 1
    ja init_loop
done_init:
    mov64 r0, 0
    exit

# IX: INSERT

ix_insert:
    mov64 r9, r2                  
    stxdw [r10-72], r1            

    mov64 r2, 1
    call get_account_data_ptr
    mov64 r8, r0

    mov64 r2, 0
    ldxdw r1, [r10-72]            
    call get_account_key_ptr
    mov64 r4, r0
    
    # Strict 32-Byte Authority Validation
    ldxdw r1, [r4+0]
    ldxdw r3, [r8+ST_AUTHORITY+0]
    jne r1, r3, insert_err_auth
    ldxdw r1, [r4+8]
    ldxdw r3, [r8+ST_AUTHORITY+8]
    jne r1, r3, insert_err_auth
    ldxdw r1, [r4+16]
    ldxdw r3, [r8+ST_AUTHORITY+16]
    jne r1, r3, insert_err_auth
    ldxdw r1, [r4+24]
    ldxdw r3, [r8+ST_AUTHORITY+24]
    jeq r1, r3, insert_auth_ok
insert_err_auth:
    mov64 r0, 6 # ERR_WRONG_AUTHORITY
    exit
insert_auth_ok:

    # Extract Leaf 
    mov64 r4, r9
    add64 r4, 1                   
    
    mov64 r6, r10
    sub64 r6, 64
    mov64 r1, r6
    mov64 r2, r4
    mov64 r3, 32
    call sol_memcpy_

    # Verify Leaf is not Zero
    ldxdw r0, [r6+0]
    ldxdw r3, [r6+8]
    or64 r0, r3
    ldxdw r3, [r6+16]
    or64 r0, r3
    ldxdw r3, [r6+24]
    or64 r0, r3
    jne r0, 0, insert_leaf_ok
    mov64 r0, 8 # ERR_ZERO_LEAF
    exit
insert_leaf_ok:

    # Ensure Tree space
    ldxw r7, [r8+ST_NEXT_INDEX]   
    mov64 r0, 1
    lsh64 r0, DEPTH
    jlt r7, r0, insert_space_ok
    mov64 r0, 7 # ERR_TREE_FULL
    exit
insert_space_ok:

    mov64 r5, 0                   
    stxdw [r10-80], r5            
loop_insert:
    ldxdw r5, [r10-80]
    jge r5, DEPTH, end_insert_loop
    
    mov64 r4, r7
    and64 r4, 1
    jeq r4, 1, ins_right

ins_left:
    mov64 r1, r8
    add64 r1, ST_FILLED_SUBTREES
    ldxdw r5, [r10-80]
    mov64 r2, r5
    mul64 r2, HASH_SIZE
    add64 r1, r2
    mov64 r2, r6
    mov64 r3, 32
    call sol_memcpy_

    ldxdw r1, [r10-80]
    mov64 r2, r6
    add64 r2, 32
    call load_zero_hash
    ja ins_perform_hash

ins_right:
    mov64 r1, r6
    add64 r1, 32
    mov64 r2, r6
    mov64 r3, 32
    call sol_memcpy_

    mov64 r1, r6
    mov64 r2, r8
    add64 r2, ST_FILLED_SUBTREES
    ldxdw r5, [r10-80]
    mov64 r3, r5
    mul64 r3, HASH_SIZE
    add64 r2, r3
    mov64 r3, 32
    call sol_memcpy_

ins_perform_hash:
    mov64 r1, r10
    sub64 r1, 112                 
    stxdw [r1+0], r6              
    mov64 r2, 64
    stxdw [r1+8], r2              

    mov64 r2, 1                   
    mov64 r3, r6                  
    call sol_sha256

    rsh64 r7, 1
    ldxdw r5, [r10-80]            
    add64 r5, 1
    stxdw [r10-80], r5            
    ja loop_insert

end_insert_loop:
    mov64 r1, r8
    add64 r1, ST_CURRENT_ROOT
    mov64 r2, r6
    mov64 r3, 32
    call sol_memcpy_

    ldxw r7, [r8+ST_NEXT_INDEX]
    add64 r7, 1
    stxw [r8+ST_NEXT_INDEX], r7
    mov64 r0, 0
    exit

# IX: VERIFY

ix_verify:
    mov64 r9, r2                  
    stxdw [r10-72], r1            

    mov64 r2, 1
    call get_account_data_ptr
    mov64 r8, r0

    # Extract Index
    mov64 r4, r9
    add64 r4, 33
    ldxb r7, [r4+0]
    ldxb r0, [r4+1]
    lsh64 r0, 8
    or64 r7, r0
    ldxb r0, [r4+2]
    lsh64 r0, 16
    or64 r7, r0
    ldxb r0, [r4+3]
    lsh64 r0, 24
    or64 r7, r0

    mov64 r4, r9
    add64 r4, 37                  
    stxdw [r10-88], r4            

    mov64 r6, r10
    sub64 r6, 64
    
    mov64 r4, r9
    add64 r4, 1
    mov64 r1, r6
    mov64 r2, r4
    mov64 r3, 32
    call sol_memcpy_

    mov64 r5, 0                   
    stxdw [r10-80], r5            
loop_verify:
    ldxdw r5, [r10-80]
    jge r5, DEPTH, end_verify
    
    mov64 r3, r7
    and64 r3, 1
    jeq r3, 1, ver_right

ver_left:
    mov64 r1, r6
    add64 r1, 32
    ldxdw r2, [r10-88]            
    mov64 r3, 32
    call sol_memcpy_
    ja ver_hash

ver_right:
    mov64 r1, r6
    add64 r1, 32
    mov64 r2, r6
    mov64 r3, 32
    call sol_memcpy_
    
    mov64 r1, r6
    ldxdw r2, [r10-88]            
    mov64 r3, 32
    call sol_memcpy_

ver_hash:
    mov64 r1, r10
    sub64 r1, 112
    stxdw [r1+0], r6
    mov64 r2, 64
    stxdw [r1+8], r2

    mov64 r2, 1
    mov64 r3, r6
    call sol_sha256

    ldxdw r4, [r10-88]
    add64 r4, 32                  
    stxdw [r10-88], r4            
    
    rsh64 r7, 1                   
    ldxdw r5, [r10-80]
    add64 r5, 1
    stxdw [r10-80], r5
    ja loop_verify

end_verify:
    mov64 r1, r6
    mov64 r2, r8
    add64 r2, ST_CURRENT_ROOT
    mov64 r3, 32
    mov64 r4, r10
    sub64 r4, 120
    call sol_memcmp_

    ldxw r5, [r10-120]            
    jeq r5, 0, verify_ok
    mov64 r0, 9 # ERR_INVALID_PROOF
    exit
verify_ok:
    mov64 r0, 0
    exit



# ZERO HASH TABLE

load_zero_hash:
    jeq r1, 0, zero_hash_0
    jeq r1, 1, zero_hash_1
    jeq r1, 2, zero_hash_2
    jeq r1, 3, zero_hash_3
    jeq r1, 4, zero_hash_4
    jeq r1, 5, zero_hash_5
    jeq r1, 6, zero_hash_6
    jeq r1, 7, zero_hash_7
    jeq r1, 8, zero_hash_8
    jeq r1, 9, zero_hash_9
    jeq r1, 10, zero_hash_10
    jeq r1, 11, zero_hash_11
    jeq r1, 12, zero_hash_12
    jeq r1, 13, zero_hash_13
    jeq r1, 14, zero_hash_14
    jeq r1, 15, zero_hash_15
    jeq r1, 16, zero_hash_16
    jeq r1, 17, zero_hash_17
    jeq r1, 18, zero_hash_18
    jeq r1, 19, zero_hash_19
    jeq r1, 20, zero_hash_20
    exit

zero_hash_0:
    lddw r0, 0x77bd62f8ad7a6866
    stxdw [r2+0], r0
    lddw r0, 0x208e9f8e8bc18f6c
    stxdw [r2+8], r0
    lddw r0, 0xb333e26e85149708
    stxdw [r2+16], r0
    lddw r0, 0x25295f0d1d592a90
    stxdw [r2+24], r0
    exit

zero_hash_1:
    lddw r0, 0x8d587f17a674eb2e
    stxdw [r2+0], r0
    lddw r0, 0x905695b952c7c080
    stxdw [r2+8], r0
    lddw r0, 0xf506b9d08296df2d
    stxdw [r2+16], r0
    lddw r0, 0xe9a46684afdb2aaa
    stxdw [r2+24], r0
    exit

zero_hash_2:
    lddw r0, 0x10eed2409a342312
    stxdw [r2+0], r0
    lddw r0, 0x01f89e88b5eb1bbd
    stxdw [r2+8], r0
    lddw r0, 0xb394ed5933c18b8c
    stxdw [r2+16], r0
    lddw r0, 0x68426e6cf90a8187
    stxdw [r2+24], r0
    exit

zero_hash_3:
    lddw r0, 0x6826aca795b6825b
    stxdw [r2+0], r0
    lddw r0, 0x9fa74f7d5fb788e1
    stxdw [r2+8], r0
    lddw r0, 0xbefcfdd1174150aa
    stxdw [r2+16], r0
    lddw r0, 0x91518a1a5c91468a
    stxdw [r2+24], r0
    exit

zero_hash_4:
    lddw r0, 0x88c684539b1f210c
    stxdw [r2+0], r0
    lddw r0, 0x5390931fac09a248
    stxdw [r2+8], r0
    lddw r0, 0x3758ae10b78c1230
    stxdw [r2+16], r0
    lddw r0, 0x5cff88ef2771c079
    stxdw [r2+24], r0
    exit

zero_hash_5:
    lddw r0, 0x241e17e1800a4656
    stxdw [r2+0], r0
    lddw r0, 0x4f0af1d3c0cd1dac
    stxdw [r2+8], r0
    lddw r0, 0x0aab60627631bf33
    stxdw [r2+16], r0
    lddw r0, 0x705dbcdcb07e1cde
    stxdw [r2+24], r0
    exit

zero_hash_6:
    lddw r0, 0xb0e5000dc42fea2d
    stxdw [r2+0], r0
    lddw r0, 0xb62b3e6453ec8baf
    stxdw [r2+8], r0
    lddw r0, 0x926b0cbd30f51486
    stxdw [r2+16], r0
    lddw r0, 0x7b417371d95e3e7d
    stxdw [r2+24], r0
    exit

zero_hash_7:
    lddw r0, 0x16305e02cf5d93ee
    stxdw [r2+0], r0
    lddw r0, 0x68a5decf9fc39e57
    stxdw [r2+8], r0
    lddw r0, 0x6a72543b5fcab48a
    stxdw [r2+16], r0
    lddw r0, 0xa12e8d651a7795c3
    stxdw [r2+24], r0
    exit

zero_hash_8:
    lddw r0, 0xbfa372bdba11a410
    stxdw [r2+0], r0
    lddw r0, 0xf771733e79829f9c
    stxdw [r2+8], r0
    lddw r0, 0x37c12b0ab8c13985
    stxdw [r2+16], r0
    lddw r0, 0x93375eb8d8c8bd91
    stxdw [r2+24], r0
    exit

zero_hash_9:
    lddw r0, 0x7299992d924a5ca1
    stxdw [r2+0], r0
    lddw r0, 0x4640c7a794276178
    stxdw [r2+8], r0
    lddw r0, 0x62f2bef6de457b9f
    stxdw [r2+16], r0
    lddw r0, 0xe772183d70c2eee2
    stxdw [r2+24], r0
    exit

zero_hash_10:
    lddw r0, 0x88ad2e1c206ee786
    stxdw [r2+0], r0
    lddw r0, 0x432e91230bedbdb8
    stxdw [r2+8], r0
    lddw r0, 0xe551f19ec8ab1b1a
    stxdw [r2+16], r0
    lddw r0, 0x91d90b3522864305
    stxdw [r2+24], r0
    exit

zero_hash_11:
    lddw r0, 0xd112bf67c509fec7
    stxdw [r2+0], r0
    lddw r0, 0x1d4ea65386cfff79
    stxdw [r2+8], r0
    lddw r0, 0x3944d48f9311cf0d
    stxdw [r2+16], r0
    lddw r0, 0xf9f7eda22046d59f
    stxdw [r2+24], r0
    exit

zero_hash_12:
    lddw r0, 0x4bd116ff5976ef07
    stxdw [r2+0], r0
    lddw r0, 0x5e40d9e719835761
    stxdw [r2+8], r0
    lddw r0, 0xcf87d970c4c5cbc9
    stxdw [r2+16], r0
    lddw r0, 0x50faa515d5ee26b4
    stxdw [r2+24], r0
    exit

zero_hash_13:
    lddw r0, 0x519b385e72fac2b7
    stxdw [r2+0], r0
    lddw r0, 0xb461c559c69ba979
    stxdw [r2+8], r0
    lddw r0, 0x91443d94ca1c88c7
    stxdw [r2+16], r0
    lddw r0, 0x0d5b381762b5cd22
    stxdw [r2+24], r0
    exit

zero_hash_14:
    lddw r0, 0x27a7a0e62ad036d5
    stxdw [r2+0], r0
    lddw r0, 0x5771fcfab207e9a6
    stxdw [r2+8], r0
    lddw r0, 0x2f5fdbe456d24475
    stxdw [r2+16], r0
    lddw r0, 0x7ccdc073dfbed522
    stxdw [r2+24], r0
    exit

zero_hash_15:
    lddw r0, 0xa758cb9ef0424caa
    stxdw [r2+0], r0
    lddw r0, 0xd4b244b6271a7e66
    stxdw [r2+8], r0
    lddw r0, 0xce3cf83c21b49fbc
    stxdw [r2+16], r0
    lddw r0, 0x9d7b47be0b35596e
    stxdw [r2+24], r0
    exit

zero_hash_16:
    lddw r0, 0x68dda1493137d42e
    stxdw [r2+0], r0
    lddw r0, 0x792a08da771d8e86
    stxdw [r2+8], r0
    lddw r0, 0x990fb86c0b47adca
    stxdw [r2+16], r0
    lddw r0, 0x6fad27c33077a9f4
    stxdw [r2+24], r0
    exit

zero_hash_17:
    lddw r0, 0x858a0ef7663b73ae
    stxdw [r2+0], r0
    lddw r0, 0xc0fd7f138d5bd72e
    stxdw [r2+8], r0
    lddw r0, 0x26372f8b2733b211
    stxdw [r2+16], r0
    lddw r0, 0xf577b482535bc279
    stxdw [r2+24], r0
    exit

zero_hash_18:
    lddw r0, 0x0b589da91775fcf2
    stxdw [r2+0], r0
    lddw r0, 0xb56989f9eb70a9c0
    stxdw [r2+8], r0
    lddw r0, 0xdbe0109c92d5d433
    stxdw [r2+16], r0
    lddw r0, 0x0bde24a75aefd791
    stxdw [r2+24], r0
    exit

zero_hash_19:
    lddw r0, 0x7b40aa748feb4748
    stxdw [r2+0], r0
    lddw r0, 0xf8ce374adb18b5ab
    stxdw [r2+8], r0
    lddw r0, 0x28d779161efd3d36
    stxdw [r2+16], r0
    lddw r0, 0xabe03897f34ab793
    stxdw [r2+24], r0
    exit

zero_hash_20:
    lddw r0, 0x39ca190075819879
    stxdw [r2+0], r0
    lddw r0, 0x95723102a0415951
    stxdw [r2+8], r0
    lddw r0, 0x670c8a492940ca14
    stxdw [r2+16], r0
    lddw r0, 0x030134f4a0669d5e
    stxdw [r2+24], r0
    exit