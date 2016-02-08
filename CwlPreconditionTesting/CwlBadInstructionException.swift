//
//  CwlBadInstructionException.swift
//  CwlPreconditionTesting
//
//  Created by Matt Gallagher on 2016/01/10.
//  Copyright © 2016 Matt Gallagher ( http://cocoawithlove.com ). All rights reserved.
//
//  Permission to use, copy, modify, and distribute this software for any purpose with or without
//  fee is hereby granted, provided that the above copyright notice and this permission notice
//  appear in all copies.
//
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
//  SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
//  AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
//  NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
//  OF THIS SOFTWARE.
//

import Foundation

private func raiseBadInstructionException() {
	BadInstructionException().raise()
}

@objc public class BadInstructionException: NSException {
	static var name: String = "BadInstruction"

	init() {
		super.init(name: BadInstructionException.name, reason: nil, userInfo: nil)
	}
	
	required public init?(coder aDecoder: NSCoder) {
		super.init(coder: aDecoder)
	}
	
	public static func catch_mach_exception_raise_state(exception_port: mach_port_t, exception: exception_type_t, code: UnsafePointer<mach_exception_data_type_t>, codeCnt: mach_msg_type_number_t, flavor: UnsafeMutablePointer<Int32>, old_state: UnsafePointer<natural_t>, old_stateCnt: mach_msg_type_number_t, new_state: thread_state_t, new_stateCnt: UnsafeMutablePointer<mach_msg_type_number_t>) -> kern_return_t {

	#if arch(x86_64)
		// Make sure we've been given enough memory
		if old_stateCnt != x86_THREAD_STATE64_COUNT || new_stateCnt.memory < x86_THREAD_STATE64_COUNT {
			return KERN_INVALID_ARGUMENT
		}
		
		// Read the old thread state
		var state = UnsafePointer<x86_thread_state64_t>(old_state).memory

		// 1. Decrement the stack pointer
		state.__rsp -= __uint64_t(sizeof(Int))
		
		// 2. Save the old Instruction Pointer to the stack.
		UnsafeMutablePointer<__uint64_t>(bitPattern: UInt(state.__rsp)).memory = state.__rip

		// 3. Set the Instruction Pointer to the new function's address
		var f: @convention(c) () -> Void = raiseBadInstructionException
		withUnsafePointer(&f) { state.__rip = UnsafePointer<__uint64_t>($0).memory }
		
		// Write the new thread state
		UnsafeMutablePointer<x86_thread_state64_t>(new_state).memory = state
		new_stateCnt.memory = x86_THREAD_STATE64_COUNT
	#endif
	
		return KERN_SUCCESS
	}
}