/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2019, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#ifndef _CAM_OIS_CORE_H_
#define _CAM_OIS_CORE_H_

#include <linux/cma.h>
#include "cam_ois_dev.h"

#define OIS_NAME_LEN 64
#define OIS_ENDIANNESS_MASK_FW              0x0F
#define OIS_ENDIANNESS_MASK_INPUTPARAM      0xF0

#define MAX_FW_COUNT                        4
#define MAX_CAM_COUNT                       2

struct fw_ctl
{
	int  fw_count;
	char *fw_name[MAX_FW_COUNT];
	struct firmware *fw[MAX_FW_COUNT];
};

/**
 * @power_info: power setting info to control the power
 *
 * This API construct the default ois power setting.
 *
 * @return Status of operation. Negative in case of error. Zero otherwise.
 */
int32_t cam_ois_construct_default_power_setting(
	struct cam_sensor_power_ctrl_t *power_info);


int cam_ois_driver_cmd(struct cam_ois_ctrl_t *e_ctrl, void *arg);

/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API handles the shutdown ioctl/close
 */
void cam_ois_shutdown(struct cam_ois_ctrl_t *o_ctrl);

struct completion *cam_ois_get_i3c_completion(uint32_t index);

/*xiaomi add begin*/
/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API init ois parklens info of o_ctrl
 */
int32_t init_ois_parklens_info(struct cam_ois_ctrl_t *o_ctrl);

/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API deinit parklens info of o_ctrl
 */
int32_t ois_deinit_parklens_info(struct cam_ois_ctrl_t *o_ctrl);

/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API query whether parklens power down or not
 */
bool ois_parklens_power_down(struct cam_ois_ctrl_t *o_ctrl);

/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API trigger a thread to do parklens
 */
int32_t ois_parklens_thread_trigger(struct cam_ois_ctrl_t *o_ctrl);

/**
 * @o_ctrl: OIS ctrl structure
 *
 * This API stop parklens thread
 */
int32_t ois_parklens_thread_stop(struct cam_ois_ctrl_t *o_ctrl, enum parklens_opcodes opcode);
/*xiaomi add end*/
#endif
/* _CAM_OIS_CORE_H_ */
