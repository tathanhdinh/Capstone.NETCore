using System;
using System.Runtime.InteropServices;

namespace Gee.External.Capstone {
    /// <summary>
    ///     Capstone Import.
    /// </summary>
    public static class CapstoneImport {
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_version")]
        public static extern uint Version(ref int major, ref int minor);

        /// <summary>
        ///     Ask for archs/modes supported by Capstone
        /// </summary>
        /// <param name="query">
        ///     
        /// </param>
        /// <returns></returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_support")]
        public static extern bool Support(int query);

        /// <summary>
        ///     Open a Capstone Handle.
        /// </summary>
        /// <param name="architecture">
        ///     An integer indicating the disassemble architecture.
        /// </param>
        /// <param name="mode">
        ///     An integer indicating the disassemble mode.
        /// </param>
        /// <param name="handle">
        ///     A pointer to a Capstone handle.
        /// </param>
        /// <returns>
        ///     An integer indicating the result of the operation.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_open")]
        public static extern int Open(int architecture, int mode, ref IntPtr handle);

        /// <summary>
        ///     Close a Capstone Handle.
        /// </summary>
        /// <param name="handle">
        ///     A Capstone handle.
        /// </param>
        /// <returns>
        ///     An integer indicating the result of the operation.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_close")]
        public static extern int Close(ref IntPtr handle);

        /// <summary>
        ///     Set a Disassemble Option.
        /// </summary>
        /// <param name="handle">
        ///     A Capstone handle.
        /// </param>
        /// <param name="option">
        ///     An integer indicating the option to set.
        /// </param>
        /// <param name="value">
        ///     A platform specific integer indicating the value to set.
        /// </param>
        /// <returns>
        ///     An integer indicating the result of the operation.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_option")]
        public static extern int SetOption(UIntPtr handle, int option, UIntPtr value);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_errno")]
        public static extern int GetLastError(UIntPtr handle);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_strerrno")]
        public static extern IntPtr FormatMessage(int code);

        /// <summary>
        ///     Disassemble Binary Code.
        /// </summary>
        /// <param name="pHandle">
        ///     A pointer to a Capstone handle.
        /// </param>
        /// <param name="pCode">
        ///     A pointer to a collection of bytes representing the binary code to disassemble.
        /// </param>
        /// <param name="codeSize">
        ///     A platform specific integer representing the number of instructions to disassemble.
        /// </param>
        /// <param name="startingAddress">
        ///     The address of the first instruction in the collection of bytes to disassemble.
        /// </param>
        /// <param name="count">
        ///     A platform specific integer representing the number of instructions to disassemble. A
        ///     <c>IntPtr.Zero</c> indicates all instructions should be disassembled.
        /// </param>
        /// <param name="instruction">
        ///     A pointer to a collection of disassembled instructions.
        /// </param>
        /// <returns>
        ///     A platform specific integer representing the number of instructions disassembled. An
        ///     <c>IntPtr.Zero</c> indicates no instructions were disassembled as a result of an error.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_disasm")]
        public static extern UIntPtr Disassemble(UIntPtr handle, IntPtr pCode, UIntPtr codeSize,
                                                 UInt64 startingAddress, UIntPtr count, ref IntPtr instruction);

        /// <summary>
        ///     Free Memory Allocated For Disassembled Instructions.
        /// </summary>
        /// <param name="pInstructions">
        ///     A pointer to a collection of disassembled instructions.
        /// </param>
        /// <param name="instructionCount">
        ///     A platform specific integer representing the number of disassembled instructions.
        /// </param>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_free")]
        public static extern void Free(IntPtr pInstructions, UIntPtr instructionCount);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_malloc")]
        public static extern IntPtr Malloc(UIntPtr handle);

        /// <summary>
        ///     Resolve a Registry Unique Identifier to an Registry Name.
        /// </summary>
        /// <param name="handle">
        ///     A Capstone handle.
        /// </param>
        /// <param name="id">
        ///     A registry's unique identifier.
        /// </param>
        /// <returns>
        ///     A pointer to a string representing the registry's name. An <c>IntPtr.Zero</c> indicates the
        ///     registry's unique identifier is invalid.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_reg_name")]
        public static extern IntPtr RegistryName(UIntPtr handle, uint id);

        /// <summary>
        ///     Resolve an Instruction Unique Identifier to an Instruction Name.
        /// </summary>
        /// <param name="handle">
        ///     A Capstone handle.
        /// </param>
        /// <param name="id">
        ///     An instruction's unique identifier.
        /// </param>
        /// <returns>
        ///     A pointer to a string representing the instruction's name. An <c>IntPtr.Zero</c> indicates the
        ///     instruction's unique identifier is invalid.
        /// </returns>
        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_insn_name")]
        public static extern IntPtr InstructionName(UIntPtr handle, uint id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_group_name")]
        public static extern IntPtr GroupName(UIntPtr handle, uint id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_insn_group")]
        public static extern IntPtr InstructionGroup(UIntPtr handle, IntPtr pInstruction, uint id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_reg_read")]
        public static extern bool IsRegisterRead(UIntPtr handle, IntPtr pInstruction, uint id);

        [DllImport("capstone.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "cs_reg_write")]
        public static extern bool IsRegisterWrite(UIntPtr handle, IntPtr pInstruction, uint id);
    }
}
