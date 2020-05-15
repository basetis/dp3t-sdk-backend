/*
 * Copyright (c) 2020 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.dpppt.backend.sdk.ws.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.ByteString;
import org.dpppt.backend.sdk.data.DPPPTDataService;
import org.dpppt.backend.sdk.data.EtagGeneratorInterface;
import org.dpppt.backend.sdk.model.*;
import org.dpppt.backend.sdk.model.proto.Exposed;
import org.dpppt.backend.sdk.ws.security.JWTGenerator;
import org.dpppt.backend.sdk.ws.security.OTPKeyGenerator;
import org.dpppt.backend.sdk.ws.security.OTPManager;
import org.dpppt.backend.sdk.ws.security.ValidateRequest;
import org.dpppt.backend.sdk.ws.security.ValidateRequest.InvalidDateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import javax.validation.Valid;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
@RequestMapping("/v1")
public class DPPPTController {

	private final DPPPTDataService dataService;
	private final EtagGeneratorInterface etagGenerator;
	private final String appSource;
	private final int exposedListCacheContol;
	private final ValidateRequest validateRequest;
	private final int retentionDays;

	private final long batchLength;

	private final long requestTime;
	@Autowired
	private ObjectMapper jacksonObjectMapper;

	@Value("${ws.app.otp.seedKey}")
	private String seedKey;

	@Value("${ws.app.jwt.privatekey}")
	private String jwtPrivate;

	public DPPPTController(DPPPTDataService dataService, EtagGeneratorInterface etagGenerator, String appSource,
			int exposedListCacheControl, ValidateRequest validateRequest, long batchLength, int retentionDays, long requestTime) {
		this.dataService = dataService;
		this.appSource = appSource;
		this.etagGenerator = etagGenerator;
		this.exposedListCacheContol = exposedListCacheControl;
		this.validateRequest = validateRequest;
		this.batchLength = batchLength;
		this.retentionDays = retentionDays;
		this.requestTime = requestTime;
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "")
	public @ResponseBody ResponseEntity<String> hello() {
		return ResponseEntity.ok().header("X-HELLO", "dp3t").body("Hello from DP3T WS");
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "/otp/{numberOfDigits}")
	public @ResponseBody ResponseEntity<String> getOTP(@PathVariable Integer numberOfDigits) throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {
		OTPKeyGenerator otpKeyGenerator = new OTPKeyGenerator(seedKey);
		String otp = otpKeyGenerator.getOneTimePassword("TOTP", numberOfDigits, true);
		HttpHeaders headers = new HttpHeaders();
		headers.add("X-OTP", otp);

		return ResponseEntity.ok().headers(headers).body("Your OTP is...");
	}
	
	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "/onset/{authorizationCode}/{fake}/{validationType}")
	public @ResponseBody ResponseEntity<OnSetResponse> onSet(@PathVariable String authorizationCode, @PathVariable Integer fake, @PathVariable String validationType)  {
		OnSetResponse onSetResponse = new OnSetResponse();
		if (validationType == null || validationType.isEmpty()) {
			onSetResponse.setError("Invalid validationType");
			return new ResponseEntity<>(onSetResponse, HttpStatus.BAD_REQUEST);
		}
		switch (validationType) {
			case "OTP":
				return otpOnSet(authorizationCode, fake, onSetResponse);
			case "VOTTUN":
				return vottunOnSet(authorizationCode, fake, onSetResponse);
			default:
				onSetResponse.setError("Invalid validationType");
				return new ResponseEntity<>(onSetResponse, HttpStatus.BAD_REQUEST);
		}
	}
	private ResponseEntity<OnSetResponse> otpOnSet(@PathVariable String authorizationCode, @PathVariable Integer fake, OnSetResponse onSetResponse) {
		try {
			OTPManager.getInstance().checkPassword(authorizationCode);
			JWTGenerator jwtGenerator = new JWTGenerator(jwtPrivate);
			OffsetDateTime expiresAt = OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).plusYears(1);
			String jwtToken = jwtGenerator.createToken(expiresAt, fake);
			onSetResponse.setAccessToken(jwtToken);
		} catch(InvalidParameterException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			onSetResponse.setError(e.getMessage());
		}
		onSetResponse.setFake(fake);
		return ResponseEntity.ok().body(onSetResponse);
	}

	private ResponseEntity<OnSetResponse> vottunOnSet(@PathVariable String authorizationCode, @PathVariable Integer fake, OnSetResponse onSetResponse) {
		onSetResponse.setError("Not Implemented");
		return ResponseEntity.ok().body(onSetResponse);
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@PostMapping(value = "/exposed")
	public @ResponseBody ResponseEntity<String> addExposee(@Valid @RequestBody ExposeeRequest exposeeRequest,
			@RequestHeader(value = "User-Agent", required = true) String userAgent,
			@AuthenticationPrincipal Object principal) throws InvalidDateException {
		long now = System.currentTimeMillis();
		if (!this.validateRequest.isValid(principal)) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
		}
		if (!isValidBase64(exposeeRequest.getKey())) {
			return new ResponseEntity<>("No valid base64 key", HttpStatus.BAD_REQUEST);
		}
		// TODO: should we give that information?
		Exposee exposee = new Exposee();
		exposee.setKey(exposeeRequest.getKey());
		long keyDate = this.validateRequest.getKeyDate(principal, exposeeRequest);

		exposee.setKeyDate(keyDate);
		if(!this.validateRequest.isFakeRequest(principal, exposeeRequest)) {
			dataService.upsertExposee(exposee, appSource);
		} 
		
		long after = System.currentTimeMillis();
		long duration = after - now;
		try{
			Thread.sleep(Math.max(this.requestTime - duration,0));
		}
		catch (Exception ex) {
			
		}
		return ResponseEntity.ok().build();
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "/exposedjson/{batchReleaseTime}", produces = "application/json")
	public @ResponseBody ResponseEntity<ExposedOverview> getExposedByDayDate(@PathVariable Long batchReleaseTime,
			WebRequest request) {
		if (batchReleaseTime % batchLength != 0) {
			return ResponseEntity.badRequest().build();
		}
		if (batchReleaseTime > OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli()) {
			return ResponseEntity.notFound().build();
		}
		if (batchReleaseTime < OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).minusDays(retentionDays).toInstant().toEpochMilli()){
			return ResponseEntity.notFound().build();
		}

		int max = dataService.getMaxExposedIdForBatchReleaseTime(batchReleaseTime, batchLength);
		String etag = etagGenerator.getEtag(max, "json");
		if (request.checkNotModified(etag)) {
			return ResponseEntity.status(HttpStatus.NOT_MODIFIED).build();
		} else {
			List<Exposee> exposeeList = dataService.getSortedExposedForBatchReleaseTime(batchReleaseTime, batchLength);
			ExposedOverview overview = new ExposedOverview(exposeeList);
			overview.setBatchReleaseTime(batchReleaseTime);
			return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(exposedListCacheContol)))
					.header("X-BATCH-RELEASE-TIME", batchReleaseTime.toString()).body(overview);
		}
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "/exposed/{batchReleaseTime}", produces = "application/x-protobuf")
	public @ResponseBody ResponseEntity<Exposed.ProtoExposedList> getExposedByBatch(@PathVariable Long batchReleaseTime,
			WebRequest request) {
		if (batchReleaseTime % batchLength != 0) {
			return ResponseEntity.badRequest().build();
		}
		if (batchReleaseTime > OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli()) {
			return ResponseEntity.notFound().build();
		}
		if (batchReleaseTime < OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC).minusDays(retentionDays).toInstant().toEpochMilli()){
			return ResponseEntity.notFound().build();
		}
		int max = dataService.getMaxExposedIdForBatchReleaseTime(batchReleaseTime, batchLength);
		String etag = etagGenerator.getEtag(max, "proto");
		if (request.checkNotModified(etag)) {
			return ResponseEntity.status(HttpStatus.NOT_MODIFIED).build();
		} else {
			List<Exposee> exposeeList = dataService.getSortedExposedForBatchReleaseTime(batchReleaseTime, batchLength);
			List<Exposed.ProtoExposee> exposees = new ArrayList<>();
			for (Exposee exposee : exposeeList) {
				Exposed.ProtoExposee protoExposee = Exposed.ProtoExposee.newBuilder()
						.setKey(ByteString.copyFrom(Base64.getDecoder().decode(exposee.getKey())))
						.setKeyDate(exposee.getKeyDate()).build();
				exposees.add(protoExposee);
			}
			Exposed.ProtoExposedList protoExposee = Exposed.ProtoExposedList.newBuilder().addAllExposed(exposees)
					.setBatchReleaseTime(batchReleaseTime).build();

			return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(exposedListCacheContol)))
					.header("X-BATCH-RELEASE-TIME", batchReleaseTime.toString()).body(protoExposee);
		}
	}

	@CrossOrigin(origins = { "https://editor.swagger.io" })
	@GetMapping(value = "/buckets/{dayDateStr}", produces = "application/json")
	public @ResponseBody ResponseEntity<BucketList> getListOfBuckets(@PathVariable String dayDateStr) {
		OffsetDateTime day = LocalDate.parse(dayDateStr).atStartOfDay().atOffset(ZoneOffset.UTC);
		OffsetDateTime currentBucket = day;
		OffsetDateTime now = OffsetDateTime.now().withOffsetSameInstant(ZoneOffset.UTC);
		List<Long> bucketList = new ArrayList<>();
		while(currentBucket.toInstant().toEpochMilli() < Math.min(day.plusDays(1).toInstant().toEpochMilli(), now.toInstant().toEpochMilli())) {
			bucketList.add(currentBucket.toInstant().toEpochMilli());
			currentBucket = currentBucket.plusSeconds(batchLength/1000);
		}
		BucketList list = new BucketList();
		list.setBuckets(bucketList);
		return ResponseEntity.ok(list);
	}


	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ResponseEntity<Object> invalidArguments() {
		return ResponseEntity.badRequest().build();
	}

	@ExceptionHandler(InvalidDateException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ResponseEntity<Object> invalidDate() {
		return ResponseEntity.badRequest().build();
	}

	private boolean isValidBase64(String value) {
		try {
			Base64.getDecoder().decode(value);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

}
